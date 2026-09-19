//! HTTP/3 MASQUE (`CONNECT-UDP`, RFC 9298) server.
//!
//! This module terminates a QUIC/HTTP/3 connection and relays UDP datagrams
//! between the client and a single upstream target named by the request's
//! `:authority`. HTTP/3 MASQUE clients (e.g. Chrome) tunnel QUIC packets as
//! HTTP/3 DATAGRAMs (RFC 9297) whose payload is a `DATAGRAM` capsule
//! (RFC 9297 §4 / RFC 9298 §4) carrying the raw UDP payload.
//!
//! Design notes (resolved empirically against the 0.0.x crates):
//!
//! * `h3-datagram`'s `DatagramSender`/`DatagramReader` hold their *own* cloned
//!   `quinn::Connection` (see `h3-quinn`'s `SendDatagramHandler`/`RecvDatagramHandler`),
//!   so calling `get_datagram_sender`/`get_datagram_reader` on the per-connection
//!   `h3::server::Connection` yields owned handles that do **not** borrow it. This
//!   lets us run a single connection-wide datagram *reader* task that demultiplexes
//!   by QUIC stream id, while each accepted `CONNECT-UDP` request gets its own
//!   `DatagramSender` and runs in its own task. => multiple concurrent
//!   `CONNECT-UDP` streams per QUIC connection (Chrome multiplexes) are supported.
//! * The h3-datagram layer automatically prepends/strips the Quarter Stream ID
//!   (stream id / 4) to the wire datagram, so the bytes we hand to / receive from
//!   it are exactly the RFC 9297 capsule (`Type=0x00` + `Length` + `Value`).

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
use base64::Engine;
use bytes::{BufMut, Bytes, BytesMut};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use h3::{
    ext::Protocol,
    quic::{self, StreamId},
    server::{Connection as H3Connection, RequestStream},
};
use h3_datagram::datagram_handler::{DatagramReader, DatagramSender, HandleDatagramsExt};
use h3_quinn::datagram::{RecvDatagramHandler, SendDatagramHandler};
use h3_quinn::Connection as H3QuinnConnection;
use quinn::{
    crypto::rustls::QuicServerConfig, Connection as QuinnConnection, Endpoint, ServerConfig,
    TransportConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
};
use tracing::{debug, info, warn};

use crate::config::AppConfig;
use crate::server::{
    Host, Resolver, UDP_PACKET_MAX_LEN, is_rfc6890_special, log_request,
};

/// Concrete HTTP/3 connection type we use (h3 over quinn, `Bytes` buffers).
type H3Conn = H3Connection<H3QuinnConnection, Bytes>;

/// Owned datagram sender for one CONNECT-UDP stream.
type H3Sender = DatagramSender<SendDatagramHandler, Bytes>;

/// Owned connection-wide datagram reader.
type H3Reader = DatagramReader<RecvDatagramHandler>;

/// Per-stream channel used by the reader task to hand demultiplexed
/// (QSID-stripped) datagram capsules to the owning tunnel task.
type Rx = mpsc::UnboundedReceiver<Bytes>;

/// Routing table: QUIC stream id -> tunnel task inbox.
type Routes = Arc<Mutex<HashMap<StreamId, mpsc::UnboundedSender<Bytes>>>>;

/// Headroom (bytes) we budget for the QUIC DATAGRAM frame header, the
/// Quarter Stream ID varint, and the capsule's `Type`/`Length` varints when
/// deciding whether an outgoing capsule fits the current datagram MTU.
const DATAGRAM_OVERHEAD: usize = 8;

const BASE64_ENGINE: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// HTTP/3 MASQUE server. Created from the shared `AppConfig`; runs the QUIC
/// listener and, for every QUIC connection, an HTTP/3 connection driver plus a
/// connection-wide datagram demultiplexer.
pub struct MasqueServer {
    config: AppConfig,
}

impl MasqueServer {
    pub fn new(config: AppConfig) -> anyhow::Result<Self> {
        // Fail fast if the crypto material is missing or unreadable. The CLI
        // already requires these via `required_if_eq`, but verify eagerly so a
        // bad path surfaces at startup rather than on first handshake.
        if config.key.is_none() || config.cert_chain.is_none() || config.auth_token.is_none() {
            anyhow::bail!(
                "--enable h3 requires --key, --cert-chain and --auth-token to be set"
            );
        }
        Ok(Self { config })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let certs = load_certs(self.config.cert_chain.as_deref().unwrap()).await?;
        let key = load_key(self.config.key.as_deref().unwrap()).await?;

        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("failed to build rustls ServerConfig from --key/--cert-chain")?;
        // Allow 0-RTT / early data so MASQUE handshakes can be fast; harmless
        // for our stateless tunnel.
        tls.max_early_data_size = u32::MAX;
        tls.alpn_protocols = vec![b"h3".to_vec()];

        let quic_crypto = QuicServerConfig::try_from(tls)
            .context("failed to build QUIC crypto config from rustls ServerConfig")?;
        let mut server_cfg = ServerConfig::with_crypto(Arc::new(quic_crypto));

        let mut tp = TransportConfig::default();
        // NOTE: `None` DISABLES inbound datagrams — we need them, so pass Some.
        // There is no `max_datagram_receive_frame_size` in quinn 0.11.
        tp.datagram_receive_buffer_size(Some(64 * 1024));
        tp.datagram_send_buffer_size(64 * 1024);
        server_cfg.transport_config(Arc::new(tp));

        // Reuse --listen's IP; only the UDP port differs (default 443).
        let addr = SocketAddr::new(self.config.listen.ip(), self.config.udp_port);
        let endpoint = Endpoint::server(server_cfg, addr)
            .with_context(|| format!("failed to bind MASQUE/QUIC endpoint on {addr}"))?;

        info!(listen = %addr, "masque (HTTP/3 CONNECT-UDP) server started");

        // A single resolver is shared (cheaply cloneable) across all tunnels.
        let resolver = Resolver::new(self.config.dns_server)?;

        while let Some(incoming) = endpoint.accept().await {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "QUIC handshake failed");
                    continue;
                }
            };
            let peer = conn.remote_address();
            // Clone the raw quinn connection so the per-stream tunnel task can
            // query the live datagram MTU without borrowing the h3 connection.
            let quinn_conn = conn.clone();
            // NOTE: `H3Connection::new` uses DEFAULT settings, which disable
            // DATAGRAM and extended CONNECT — exactly the two capabilities the
            // MASQUE CONNECT-UDP protocol requires. We must build via the
            // `builder()` and advertise both, or the client will refuse to
            // negotiate the tunnel (RFC 9298/9297).
            let mut builder = h3::server::builder();
            builder.enable_datagram(true);
            builder.enable_extended_connect(true);
            let h3_conn = match builder.build(H3QuinnConnection::new(conn)).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(peer = %peer, error = %e, "HTTP/3 connection setup failed");
                    continue;
                }
            };
            let resolver = resolver.clone();
            let config = self.config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(h3_conn, peer, quinn_conn, resolver, config).await {
                    debug!(peer = %peer, error = %e, "masque connection ended");
                }
            });
        }

        Ok(())
    }
}

/// Drive one HTTP/3 connection: spawn the connection-wide datagram reader, then
/// accept `CONNECT-UDP` requests, validating and tunnelling each.
async fn handle_connection(
    mut h3_conn: H3Conn,
    peer: SocketAddr,
    quinn_conn: QuinnConnection,
    resolver: Resolver,
    config: AppConfig,
) -> anyhow::Result<()> {
    let routes: Routes = Arc::new(Mutex::new(HashMap::new()));

    // One reader for the whole connection. It owns its own quinn::Connection
    // clone, so it does not borrow `h3_conn`. It demultiplexes incoming
    // capsules to the right tunnel task by QUIC stream id.
    let mut reader: H3Reader = h3_conn.get_datagram_reader();
    let reader_routes = routes.clone();
    tokio::spawn(async move {
        loop {
            match reader.read_datagram().await {
                Ok(dgram) => {
                    let sid = dgram.stream_id();
                    let capsule = dgram.into_payload();
                    let mut guard = reader_routes.lock().await;
                    match guard.get(&sid) {
                        Some(tx) => {
                            // The tunnel task owns the UDP socket; just forward
                            // the capsule (QSID already stripped by h3-datagram).
                            if tx.send(capsule).is_err() {
                                debug!(stream = %sid, "tunnel task gone; dropping datagram");
                                guard.remove(&sid);
                            }
                        }
                        None => debug!(stream = %sid, "datagram for unknown stream; dropping"),
                    }
                }
                Err(e) => {
                    debug!(error = %e, "datagram reader ended");
                    // Drop every tunnel's sender so each tunnel task's
                    // `rx.recv()` returns `None` and exits cleanly instead of
                    // leaking after the connection closes.
                    reader_routes.lock().await.clear();
                    break;
                }
            }
        }
    });

    // Accept CONNECT-UDP requests concurrently, one task per stream.
    while let Some(resolver_req) = h3_conn.accept().await? {
        let (req, req_stream) = match resolver_req.resolve_request().await {
            Ok(v) => v,
            Err(e) => {
                warn!(peer = %peer, error = %e, "failed to resolve CONNECT-UDP request");
                continue;
            }
        };
        let stream_id = req_stream.id();
        // Owned sender for this stream (holds its own quinn::Connection clone).
        let sender: H3Sender = h3_conn.get_datagram_sender(stream_id);
        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
        routes.lock().await.insert(stream_id, tx);

        let resolver = resolver.clone();
        let config = config.clone();
        let quinn_conn = quinn_conn.clone();
        let routes = routes.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(
                req,
                req_stream,
                sender,
                rx,
                resolver,
                config,
                peer,
                stream_id,
                quinn_conn,
            )
            .await
            {
                debug!(peer = %peer, stream = %stream_id, error = %e, "CONNECT-UDP tunnel ended");
            }
            routes.lock().await.remove(&stream_id);
        });
    }

    // Accept loop ended (connection closed). Clear the routing table so any
    // tunnel tasks still awaiting `rx.recv()` observe `None` and terminate
    // rather than leaking until the process exits.
    routes.lock().await.clear();

    Ok(())
}

/// Tunnel one `CONNECT-UDP` request: validate, resolve target once, then relay
/// UDP packets <-> HTTP/3 DATAGRAM capsules for the lifetime of the stream.
#[allow(clippy::too_many_arguments)]
async fn handle_stream<S>(
    req: Request<()>,
    mut req_stream: RequestStream<S, Bytes>,
    mut sender: H3Sender,
    mut rx: Rx,
    resolver: Resolver,
    config: AppConfig,
    peer: SocketAddr,
    stream_id: StreamId,
    quinn_conn: QuinnConnection,
) -> anyhow::Result<()>
where
    S: quic::SendStream<Bytes> + quic::RecvStream,
{
    let token = config.auth_token.as_deref();

    let (host, port) = match validate_connect_udp(&req, token) {
        Ok(target) => target,
        Err(status) => {
            send_status(&mut req_stream, status).await?;
            return Ok(());
        }
    };

    let target = host.resolve(&resolver, port).await?;
    if config.block_special_addrs() && is_rfc6890_special(target.ip()) {
        warn!(
            peer = %peer,
            target = %target,
            "rejecting CONNECT-UDP to RFC 6890 special-purpose address"
        );
        send_status(&mut req_stream, StatusCode::FORBIDDEN).await?;
        anyhow::bail!("CONNECT-UDP target {target} is a special-purpose (RFC 6890) address");
    }

    log_request(peer, &host, port, "udp", target, "masque");

    // 1:1 tunnel to a single :authority target. Bind a UDP socket of the same
    // address family and connect() it so recv/send are with the target only.
    let bind_addr: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let udp = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind UDP tunnel socket on {bind_addr}"))?;
    udp.connect(target)
        .await
        .with_context(|| format!("failed to connect UDP tunnel socket to {target}"))?;

    // 200 + Capsule-Protocol: ?1, empty body. Keep the control stream OPEN for
    // the tunnel's lifetime — do NOT call finish() here.
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("capsule-protocol", "?1")
        .body(())
        .expect("valid 200 response");
    req_stream.send_response(resp).await?;

    let mut buf = vec![0u8; UDP_PACKET_MAX_LEN];
    loop {
        tokio::select! {
            // Downlink: target -> client (wrap in a DATAGRAM capsule, send via
            // HTTP/3 DATAGRAM). h3-datagram adds the Quarter Stream ID.
            read = udp.recv_from(&mut buf) => {
                let (n, _from) = match read {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(peer = %peer, target = %target, error = %e, "tunnel UDP recv failed");
                        break;
                    }
                };
                let capsule = encode_capsule(&buf[..n]);

                // QUIC datagrams are MTU-bounded (~1200 B initially). A UDP
                // packet that won't fit is dropped; RFC 9298 relies on the
                // client's own retransmission. (h3-datagram's SendDatagramError
                // variants are private in 0.0.2, so we pre-check the MTU
                // instead of matching TooLarge at runtime.)
                let too_big = match quinn_conn.max_datagram_size() {
                    Some(max) => capsule.len() + DATAGRAM_OVERHEAD > max,
                    None => true,
                };
                if too_big {
                    debug!(
                        peer = %peer,
                        len = n,
                        "UDP packet too large for QUIC datagram; dropping (client retransmit expected)"
                    );
                    continue;
                }

                if let Err(e) = sender.send_datagram(capsule) {
                    debug!(peer = %peer, error = %e, "datagram send error; ending tunnel");
                    break;
                }
            }
            // Uplink: client -> target. Reader handed us the capsule; extract the
            // raw UDP payload and write it to the upstream socket.
            got = rx.recv() => {
                match got {
                    Some(capsule) => match decode_capsule(&capsule) {
                        Some(payload) => {
                            if let Err(e) = udp.send(&payload).await {
                                debug!(peer = %peer, target = %target, error = %e, "tunnel UDP send failed");
                            }
                        }
                        None => debug!(peer = %peer, stream = %stream_id, "malformed capsule dropped"),
                    },
                    None => break, // reader task gone / connection closed
                }
            }
        }
    }

    // Control stream closed: signal tunnel teardown to the client.
    let _ = req_stream.finish().await;
    Ok(())
}

/// Validate a `CONNECT-UDP` request. Returns the resolved `(host, port)` target
/// on success, or the HTTP status code to respond with on failure.
fn validate_connect_udp(req: &Request<()>, token: Option<&str>) -> Result<(Host, u16), StatusCode> {
    if req.method() != Method::CONNECT {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    if req.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_UDP) {
        // Not a MASQUE CONNECT-UDP extended connect.
        return Err(StatusCode::NOT_IMPLEMENTED);
    }
    if req
        .headers()
        .get("capsule-protocol")
        .map(|v| v.as_bytes())
        != Some(b"?1")
    {
        // RFC 9298 requires the Capsule-Protocol indicator.
        return Err(StatusCode::BAD_REQUEST);
    }
    if !check_proxy_auth(req.headers(), token) {
        return Err(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    }
    parse_target(req).ok_or(StatusCode::BAD_REQUEST)
}

/// Authorize a CONNECT-UDP request. Accepts `Bearer <token>` and
/// `Basic <base64>` where the decoded `password` equals the token.
fn check_proxy_auth(headers: &HeaderMap, token: Option<&str>) -> bool {
    let token = match token {
        Some(t) => t,
        None => return false,
    };
    let header = match headers.get("proxy-authorization") {
        Some(h) => h,
        None => return false,
    };
    let value = match header.to_str() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if let Some(rest) = value.strip_prefix("Bearer ") {
        return rest.trim() == token;
    }
    if let Some(rest) = value.strip_prefix("Basic ")
        && let Ok(decoded) = BASE64_ENGINE.decode(rest.trim().as_bytes())
        && let Ok(s) = std::str::from_utf8(&decoded)
    {
        // RFC 7617: user:password; the password must equal the token.
        // Some clients send just the token as the whole credential.
        return if let Some((_, pass)) = s.split_once(':') {
            pass == token
        } else {
            s == token
        };
    }
    false
}

/// Extract the `:authority` host + explicit port (RFC 9298 requires a port).
fn parse_target(req: &Request<()>) -> Option<(Host, u16)> {
    let auth = req.uri().authority()?;
    let port = auth.port_u16()?; // explicit port is mandatory
    // `Authority::host()` returns an IPv6 literal *with* its brackets, so strip
    // them before parsing as an address (mirrors `parse_authority` in server.rs).
    let raw = auth.host();
    let host_str = if raw.starts_with('[') && raw.ends_with(']') {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    let host = if let Ok(ip) = host_str.parse::<IpAddr>() {
        Host::Ip(ip)
    } else {
        Host::Name(host_str.to_string())
    };
    Some((host, port))
}

async fn send_status<S: quic::SendStream<Bytes>>(
    req_stream: &mut RequestStream<S, Bytes>,
    status: StatusCode,
) -> anyhow::Result<()> {
    let mut builder = Response::builder().status(status);
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        builder = builder.header("proxy-authenticate", "Bearer");
    }
    let resp = builder.body(()).expect("valid status response");
    req_stream.send_response(resp).await?;
    Ok(())
}

/// Encode a UDP payload into an RFC 9297 `DATAGRAM` capsule:
/// `Type=0x00 (varint)` + `Length (varint)` + `Value`.
///
/// We hand-roll the QUIC/h3 variable-length integer (RFC 9000 §16) rather than
/// relying on `quinn::VarInt`'s `Codec` trait, whose trait is not re-exported
/// by `quinn` and would force a fragile transitive-dependency import. The wire
/// format is identical.
pub(crate) fn encode_capsule(payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(DATAGRAM_OVERHEAD + payload.len());
    put_varint(&mut buf, 0); // UDP_DATAGRAM = 0x00
    put_varint(&mut buf, payload.len() as u64);
    buf.extend_from_slice(payload);
    buf.freeze()
}

/// Decode a `DATAGRAM` capsule back into its raw UDP payload. Returns `None`
/// for a non-UDP_DATAGRAM type or a truncated/garbled capsule.
pub(crate) fn decode_capsule(capsule: &[u8]) -> Option<Bytes> {
    let mut buf = capsule;
    let typ = get_varint(&mut buf)?;
    if typ != 0 {
        return None; // only UDP_DATAGRAM type supported
    }
    let len = get_varint(&mut buf)? as usize;
    if buf.len() < len {
        return None;
    }
    Some(Bytes::copy_from_slice(&buf[..len]))
}

/// Encode `value` as a QUIC variable-length integer into `buf`.
fn put_varint(buf: &mut BytesMut, value: u64) {
    match value {
        0x00..=0x3f => buf.put_u8(value as u8),
        0x40..=0x3fff => buf.put_u16((value | 0x4000) as u16),
        0x4000..=0x3fff_ffff => buf.put_u32((value | 0x8000_0000) as u32),
        _ => buf.put_u64(value | 0xc000_0000_0000_0000),
    }
}

/// Decode a QUIC variable-length integer from the front of `buf`, advancing it.
fn get_varint(buf: &mut &[u8]) -> Option<u64> {
    let first = *buf.first()?;
    let len = 1 << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value: u64 = (first & 0x3f) as u64;
    for i in 1..len {
        value = (value << 8) | *buf.get(i)? as u64;
    }
    *buf = &buf[len..];
    Some(value)
}

async fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("failed to open certificate chain '{path}'"))?;
    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
        .await
        .with_context(|| format!("failed to read certificate chain '{path}'"))?;
    let mut cursor = std::io::Cursor::new(buf);
    let mut reader = std::io::BufReader::new(&mut cursor);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse PEM certificates from '{path}'"))
}

async fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("failed to open private key '{path}'"))?;
    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
        .await
        .with_context(|| format!("failed to read private key '{path}'"))?;
    let mut cursor = std::io::Cursor::new(buf);
    let mut reader = std::io::BufReader::new(&mut cursor);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("failed to parse private key from '{path}'"))?
        .with_context(|| format!("no private key found in '{path}'"))
}

#[cfg(test)]
mod tests {
    use super::{check_proxy_auth, decode_capsule, encode_capsule, parse_target, validate_connect_udp};
    use base64::Engine;
    use crate::server::Host;
    use h3::ext::Protocol;
    use http::{HeaderValue, Method, Request, Uri};

    fn connect_udp_request(uri: &str, with_capsule: bool, auth: Option<&str>) -> Request<()> {
        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri(uri.parse::<Uri>().expect("valid test uri"))
            .body(())
            .expect("valid request");
        if with_capsule {
            req.headers_mut()
                .insert("capsule-protocol", HeaderValue::from_static("?1"));
        }
        if let Some(a) = auth {
            req.headers_mut().insert(
                "proxy-authorization",
                HeaderValue::from_str(a).expect("valid auth header"),
            );
        }
        req.extensions_mut().insert(Protocol::CONNECT_UDP);
        req
    }

    #[test]
    fn capsule_round_trip_small_and_large() {
        for len in [0usize, 1, 63, 64, 100, 16383, 16384, 65535] {
            let payload = vec![0xABu8; len];
            let capsule = encode_capsule(&payload);
            let decoded = decode_capsule(&capsule).expect("decode succeeds");
            assert_eq!(decoded.as_ref(), &payload[..], "round trip failed at len {len}");
        }
    }

    #[test]
    fn capsule_rejects_unknown_type_and_truncated() {
        // Type 0x01 (not UDP_DATAGRAM) should be rejected.
        // Wire form: Type=0x01, Length=0x02, Value=[AA BB].
        let bad = vec![0x01u8, 0x02, 0xAA, 0xBB];
        assert!(decode_capsule(&bad).is_none());

        // Truncated: claims length 10 but only 3 bytes follow.
        // Wire form: Type=0x00, Length=0x0A, Value=[01 02 03].
        let trunc = vec![0x00u8, 0x0A, 0x01, 0x02, 0x03];
        assert!(decode_capsule(&trunc).is_none());
    }

    #[test]
    fn parse_target_extracts_host_and_port() {
        let req = connect_udp_request("example.com:8443", true, None);
        let (host, port) = parse_target(&req).expect("parse");
        assert_eq!(host, Host::Name("example.com".to_string()));
        assert_eq!(port, 8443);

        let req6 = connect_udp_request("[2001:db8::1]:443", true, None);
        let (host, port) = parse_target(&req6).expect("parse v6");
        assert_eq!(host, Host::Ip("2001:db8::1".parse().unwrap()));
        assert_eq!(port, 443);

        // No explicit port -> rejected.
        let no_port = connect_udp_request("example.com", true, None);
        assert!(parse_target(&no_port).is_none());
    }

    #[test]
    fn auth_header_accepts_bearer_and_basic() {
        let token = "s3cr3t";
        // Bearer
        let req = connect_udp_request("example.com:443", true, Some("Bearer s3cr3t"));
        assert!(check_proxy_auth(req.headers(), Some(token)));

        // Basic user:token
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("user:s3cr3t")
        );
        let req = connect_udp_request("example.com:443", true, Some(&basic));
        assert!(check_proxy_auth(req.headers(), Some(token)));

        // Basic with just the token as credential
        let basic2 = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("s3cr3t")
        );
        let req = connect_udp_request("example.com:443", true, Some(&basic2));
        assert!(check_proxy_auth(req.headers(), Some(token)));
    }

    #[test]
    fn auth_header_rejects_wrong_or_missing() {
        let token = "s3cr3t";
        // Wrong bearer
        let req = connect_udp_request("example.com:443", true, Some("Bearer wrong"));
        assert!(!check_proxy_auth(req.headers(), Some(token)));

        // Basic with wrong password
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("user:nope")
        );
        let req = connect_udp_request("example.com:443", true, Some(&basic));
        assert!(!check_proxy_auth(req.headers(), Some(token)));

        // Missing header
        let req = connect_udp_request("example.com:443", true, None);
        assert!(!check_proxy_auth(req.headers(), Some(token)));

        // No token configured at all
        let req = connect_udp_request("example.com:443", true, Some("Bearer x"));
        assert!(!check_proxy_auth(req.headers(), None));
    }

    #[test]
    fn validate_connect_udp_accepts_and_rejects() {
        let token = "s3cr3t";
        // Happy path
        let req = connect_udp_request("example.com:443", true, Some("Bearer s3cr3t"));
        let (host, port) = validate_connect_udp(&req, Some(token)).expect("ok");
        assert_eq!(host, Host::Name("example.com".to_string()));
        assert_eq!(port, 443);

        // Wrong method
        let mut bad = connect_udp_request("example.com:443", true, Some("Bearer s3cr3t"));
        *bad.method_mut() = Method::GET;
        assert_eq!(
            validate_connect_udp(&bad, Some(token)).unwrap_err(),
            http::StatusCode::METHOD_NOT_ALLOWED
        );

        // Missing capsule-protocol
        let no_cap = connect_udp_request("example.com:443", false, Some("Bearer s3cr3t"));
        assert_eq!(
            validate_connect_udp(&no_cap, Some(token)).unwrap_err(),
            http::StatusCode::BAD_REQUEST
        );

        // Missing auth
        let no_auth = connect_udp_request("example.com:443", true, None);
        assert_eq!(
            validate_connect_udp(&no_auth, Some(token)).unwrap_err(),
            http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
        );

        // Not extended-connect (no :protocol)
        let mut no_proto = connect_udp_request("example.com:443", true, Some("Bearer s3cr3t"));
        no_proto.extensions_mut().clear();
        assert_eq!(
            validate_connect_udp(&no_proto, Some(token)).unwrap_err(),
            http::StatusCode::NOT_IMPLEMENTED
        );
    }
}

/// Real end-to-end test: drive the actual `MasqueServer` with a `quinn` + `h3`
/// client over a freshly generated self-signed certificate. The client opens a
/// `CONNECT-UDP` tunnel to a local UDP echo socket, then round-trips a UDP
/// payload through HTTP/3 DATAGRAM capsules. This exercises the two defects the
/// bind-only smoke test cannot catch:
///
///   * the server MUST advertise DATAGRAM + extended-CONNECT settings, or the
///     client handshake / `send_request` fails;
///   * datagrams must flow both ways through the tunnel.
///
/// Marked `#[ignore]` (and a no-op if `openssl` is absent) so it does not run in
/// the default `cargo test` (needs openssl + a network namespace) — run it with
/// `cargo test -- --ignored e2e_connect_udp_roundtrip`.
#[cfg(test)]
mod e2e {
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::process::Command as SyncCommand;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::anyhow;
    use bytes::Bytes;
    use clap::Parser;
    use http::{HeaderValue, Method, Request, StatusCode};
    use h3::ext::Protocol;
    use h3_datagram::datagram_handler::HandleDatagramsExt;
    use h3_quinn::Connection as H3QuinnConnection;
    use quinn::{ClientConfig, Endpoint, TransportConfig};
    use rustls::RootCertStore;
    use rustls::crypto::ring;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    use crate::config::Cli;
    use super::{MasqueServer, decode_capsule, encode_capsule};

    const TOKEN: &str = "test-masque-token";

    /// Generate a self-signed cert + key with localhost / 127.0.0.1 SANs into a
    /// temp dir. Returns `(key_path, cert_path)`. Returns `None` if openssl is
    /// unavailable.
    fn gen_cert() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
        let openssl = which("openssl")?;
        let dir = std::env::temp_dir().join(format!("auto-server-masque-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let key = dir.join("key.pem");
        let cert = dir.join("cert.pem");
        let status = SyncCommand::new(openssl)
            .arg("req")
            .arg("-x509")
            .arg("-newkey")
            .arg("rsa:2048")
            .arg("-nodes")
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .arg("-days")
            .arg("1")
            .arg("-subj")
            .arg("/CN=localhost")
            .arg("-addext")
            .arg("subjectAltName=DNS:localhost,IP:127.0.0.1")
            .arg("-addext")
            .arg("basicConstraints=CA:FALSE")
            .arg("-addext")
            .arg("extendedKeyUsage=serverAuth")
            .arg("-addext")
            .arg("keyUsage=digitalSignature,keyEncipherment")
            .output()
            .ok()?;
        if !status.status.success() {
            return None;
        }
        if key.exists() && cert.exists() {
            Some((key, cert))
        } else {
            None
        }
    }

    fn which(name: &str) -> Option<std::path::PathBuf> {
        let out = SyncCommand::new("sh")
            .arg("-c")
            .arg(format!("command -v {name}"))
            .output()
            .ok()?;
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if p.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(p))
            }
        } else {
            None
        }
    }

    /// Grab a currently-free UDP port (TOCTOU is acceptable for a test).
    fn free_udp_port() -> u16 {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind temp udp");
        let port = s.local_addr().unwrap().port();
        drop(s);
        port
    }

    #[tokio::test]
    #[ignore = "requires openssl + network; run with: cargo test -- --ignored e2e_connect_udp_roundtrip"]
    async fn e2e_connect_udp_roundtrip() -> anyhow::Result<()> {
        let Some((key, cert)) = gen_cert() else {
            eprintln!("openssl not available; skipping e2e MASQUE test");
            return Ok(());
        };

        // ring is the crypto provider reqwest already pulled in (see Cargo.toml).
        let _ = ring::default_provider().install_default();

        let udp_port = free_udp_port();
        let cli = Cli::parse_from([
            "auto-server",
            "--listen",
            "127.0.0.1:0",
            "--enable",
            "h3",
            "--key",
            key.to_str().unwrap(),
            "--cert-chain",
            cert.to_str().unwrap(),
            "--auth-token",
            TOKEN,
            "--udp-port",
            &udp_port.to_string(),
        ]);

        let server = MasqueServer::new(cli.config)?;
        let server_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Local UDP echo socket — the single :authority target for the tunnel.
        let echo = UdpSocket::bind("127.0.0.1:0").await?;
        let echo_addr = echo.local_addr()?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, from)) = echo.recv_from(&mut buf).await {
                if echo.send_to(&buf[..n], from).await.is_err() {
                    break;
                }
            }
        });

        // --- Build a quinn + h3 client that trusts our self-signed cert. ---
        // We add the generated cert to the client's root store (SANs:
        // DNS:localhost, IP:127.0.0.1) and connect with server_name "localhost",
        // so the real webpki verifier accepts it — no custom verifier needed.
        let cert_pem = std::fs::read(&cert).map_err(|e| anyhow!("read cert: {e}"))?;
        let mut cert_reader = Cursor::new(cert_pem);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow!("parse cert: {e}"))?;
        let mut roots = RootCertStore::empty();
        for c in &certs {
            let _ = roots.add(c.clone());
        }
        let mut client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
            .map_err(|e| anyhow!("quic client crypto: {e}"))?;
        let mut client_cfg = ClientConfig::new(Arc::new(quic_crypto));
        let mut tp = TransportConfig::default();
        tp.datagram_receive_buffer_size(Some(64 * 1024));
        client_cfg.transport_config(Arc::new(tp));

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_cfg);

        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), udp_port);
        // Retry the handshake until the server has bound its listener.
        let quinn_conn = {
            let mut conn = None;
            let mut last_err: Option<String> = None;
            for _ in 0..100 {
                match endpoint.connect(server_addr, "localhost") {
                    Ok(connecting) => match connecting.await {
                        Ok(c) => {
                            conn = Some(c);
                            break;
                        }
                        Err(e) => {
                            last_err = Some(format!("handshake: {e:?}"));
                        }
                    },
                    Err(e) => {
                        last_err = Some(format!("connect: {e:?}"));
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            conn.ok_or_else(|| anyhow!("failed to connect to MASQUE server: {:?}", last_err))?
        };

        let h3_quinn_conn = H3QuinnConnection::new(quinn_conn);
        let mut builder = h3::client::builder();
        builder.enable_datagram(true);
        builder.enable_extended_connect(true);
        let (h3_conn, mut send_request) =
            builder.build(h3_quinn_conn).await.map_err(|e| anyhow!("h3 client: {e}"))?;

        // CONNECT-UDP to the echo socket.
        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://127.0.0.1:{}/", echo_addr.port()))
            .body(())
            .expect("valid CONNECT-UDP request");
        req.headers_mut()
            .insert("capsule-protocol", HeaderValue::from_static("?1"));
        req.headers_mut().insert(
            "proxy-authorization",
            HeaderValue::from_str(&format!("Bearer {TOKEN}")).expect("auth header"),
        );
        req.extensions_mut().insert(Protocol::CONNECT_UDP);

        let mut req_stream = send_request
            .send_request(req)
            .await
            .map_err(|e| anyhow!("send_request: {e}"))?;
        let resp = req_stream
            .recv_response()
            .await
            .map_err(|e| anyhow!("recv_response: {e}"))?;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "CONNECT-UDP must return 200, got {}",
            resp.status()
        );

        let stream_id = req_stream.id();
        let mut sender = h3_conn.get_datagram_sender(stream_id);

        // Client-side datagram reader: demultiplexes responses from the server.
        let mut reader = h3_conn.get_datagram_reader();
        let (dgram_tx, mut dgram_rx) = mpsc::unbounded_channel::<Bytes>();
        tokio::spawn(async move {
            while let Ok(d) = reader.read_datagram().await {
                let payload = d.into_payload();
                if dgram_tx.send(payload).is_err() {
                    break;
                }
            }
        });

        // Send a UDP payload to the echo target via a DATAGRAM capsule.
        let payload = b"masque-e2e-roundtrip-payload";
        sender
            .send_datagram(encode_capsule(payload))
            .map_err(|e| anyhow!("send_datagram: {e}"))?;

        // The echo socket bounces it back; the tunnel wraps it in a capsule.
        let got = tokio::time::timeout(Duration::from_secs(10), dgram_rx.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for echoed datagram"))?
            .ok_or_else(|| anyhow!("datagram channel closed"))?;
        let decoded = decode_capsule(&got).expect("decoded echoed capsule");
        assert_eq!(
            &decoded[..],
            payload,
            "echoed UDP payload did not round-trip through the tunnel"
        );

        // Clean up: keep handles alive until here, then tear down.
        drop(req_stream);
        drop(send_request);
        drop(h3_conn);
        endpoint.close(0u32.into(), b"test done");
        server_handle.abort();
        Ok(())
    }
}
