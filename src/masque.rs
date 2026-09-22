//! HTTP/3 MASQUE server.
//!
//! This module terminates a QUIC/HTTP/3 connection and relays traffic for three
//! request types, all dispatched from the same listener:
//!
//! 1. **`CONNECT-UDP`** (RFC 9298) — UDP payloads carried as HTTP/3 DATAGRAMs
//!    (RFC 9297): `Context ID 0` + the raw UDP payload.
//! 2. **`CONNECT-IP`** (RFC 9484) — IP packets carried as HTTP/3 DATAGRAMs:
//!    `Context ID 0` + the raw IP packet; a real layer-3 VPN gateway (needs
//!    root). Signalling capsules (`ADDRESS_ASSIGN` / `ADDRESS_REQUEST` /
//!    `ROUTE_ADVERTISEMENT`) travel on the request stream as RFC 9297 capsules.
//! 3. **Plain TCP `CONNECT`** (RFC 9114 §4.4, an extended CONNECT with *no*
//!    `:protocol`) — a pure byte pipe to the request's `:authority` target. No
//!    capsules, no DATAGRAMs, no tun; exactly like an HTTP/1.1 `CONNECT` but over
//!    HTTP/3. `h3` 0.0.8 accepts a CONNECT with no `:protocol`
//!    (`Option<Protocol>` is `None`), so this needs no dependency change.
//!
//! The three are discriminated in `handle_connection`'s accept loop (see
//! `MASQUE_IP_PATH` for why `CONNECT-IP` is path-based): `:protocol ==
//! connect-udp` → `CONNECT-UDP`; the `connect-ip` path → `CONNECT-IP`; an absent
//! `:protocol` on any other path → plain TCP `CONNECT`; any other `:protocol`
//! (e.g. `webtransport`) → `501`.
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
//! * The h3-datagram layer handles ONLY the Quarter Stream ID (stream id / 4):
//!   it prepends/strips it to/from the wire datagram. The Context ID is
//!   entirely ours: we write a Context ID varint of 0 (a single `0x00` byte)
//!   followed by the raw UDP payload / IP packet, and parse (and require)
//!   Context ID 0 on receive, dropping datagrams with any other Context ID
//!   silently (RFC 9297 §4, RFC 9298 §4.2, RFC 9484 §4.2). RFC 9297 capsule
//!   TLV framing is used only on the request stream (CONNECT-IP signalling),
//!   never in datagrams.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
// Only used by the Linux-only CONNECT-IP helpers below.
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};
// Only needed for the CONNECT-IP address pool (Linux-only data plane).
#[cfg(target_os = "linux")]
use std::sync::Mutex as StdMutex;

use anyhow::Context;
use base64::Engine;
use bytes::{Buf, BufMut, Bytes, BytesMut};
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
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{mpsc, Mutex},
    time::timeout,
};
// CONNECT-IP teardown signalling (Linux-only data plane).
#[cfg(target_os = "linux")]
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::capsule;
use crate::config::AppConfig;
// CONNECT-IP (tun/NAT) is Linux-only; see `lib.rs`.
#[cfg(target_os = "linux")]
use crate::tun::{IpPool, TunDevice};
use crate::server::{
    Host, Resolver, UDP_PACKET_MAX_LEN, is_rfc6890_special, log_request, parse_authority,
};

/// Concrete HTTP/3 connection type we use (h3 over quinn, `Bytes` buffers).
type H3Conn = H3Connection<H3QuinnConnection, Bytes>;

/// Owned datagram sender for one CONNECT-UDP stream.
type H3Sender = DatagramSender<SendDatagramHandler, Bytes>;

/// Owned connection-wide datagram reader.
type H3Reader = DatagramReader<RecvDatagramHandler>;

/// Per-stream channel used by the reader task to hand demultiplexed
/// (QSID-stripped) datagram payloads to the owning tunnel task.
type Rx = mpsc::UnboundedReceiver<Bytes>;

/// Routing table: QUIC stream id -> tunnel task inbox.
type Routes = Arc<Mutex<HashMap<StreamId, mpsc::UnboundedSender<Bytes>>>>;

/// Headroom (bytes) we budget for the QUIC DATAGRAM frame header, the
/// Quarter Stream ID varint (added by h3-datagram), and the Context ID varint
/// we prepend ourselves, when deciding whether an outgoing datagram fits the
/// current datagram MTU.
const DATAGRAM_OVERHEAD: usize = 8;

/// Fixed prefix of the default (IANA-registered) `CONNECT-UDP` URI template,
/// RFC 9298 §2:
/// `https://$PROXY_HOST:$PROXY_PORT/.well-known/masque/udp/{target_host}/{target_port}/`
const MASQUE_UDP_PATH_PREFIX: &str = "/.well-known/masque/udp/";

/// RFC 9484 §4 default `connect-ip` URI template:
/// `https://$PROXY_HOST:$PROXY_PORT/.well-known/masque/ip/`. It has **no** path
/// variables (unlike CONNECT-UDP). We dispatch on this prefix.
///
/// NOTE: h3 0.0.8 cannot surface an unknown `:protocol` token — its
/// `Protocol::from_str` rejects anything but `connect-udp`/`webtransport`, so a
/// `connect-ip` request is dropped with `H3_MESSAGE_ERROR` before our code sees
/// it (verified in `h3-0.0.8/src/proto/headers.rs` + `ext.rs`). Until h3 learns
/// `connect-ip`, this path prefix is the only reliable discriminator, and the
/// `:protocol` requirement is enforced by h3 itself once it is upgraded.
const MASQUE_IP_PATH: &str = "/.well-known/masque/ip";

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

        // Bind the QUIC endpoint to --h3-bind directly; independent of --listen
        // (which is purely the TCP proxy's bind address).
        let addr = self.config.h3_bind;
        let endpoint = Endpoint::server(server_cfg, addr)
            .with_context(|| format!("failed to bind MASQUE/QUIC endpoint on {addr}"))?;

        info!(listen = %addr, "masque (HTTP/3 CONNECT-UDP) server started");

        // A single resolver is shared (cheaply cloneable) across all tunnels.
        let resolver = Resolver::new(self.config.dns_server)?;

        // One CONNECT-IP address pool, shared across all sessions/connections so
        // allocations never collide. Validate it now (cheap) so a bad `--ip-pool`
        // fails fast at startup rather than on the first tunnel. Linux-only:
        // CONNECT-IP's tun/NAT data plane does not exist elsewhere.
        #[cfg(target_os = "linux")]
        let ip_pool = Arc::new(StdMutex::new(IpPool::new(&self.config.ip_pool)?));
        #[cfg(not(target_os = "linux"))]
        let ip_pool = ();

        while let Some(incoming) = endpoint.accept().await {
            // Available before the handshake completes, so a failed handshake
            // can still be attributed to a source.
            let peer = incoming.remote_address();
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    warn!(peer = %peer, error = %e, "QUIC handshake failed");
                    continue;
                }
            };
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
            let ip_pool = ip_pool.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(h3_conn, peer, quinn_conn, resolver, config, ip_pool).await {
                    debug!(peer = %peer, error = %e, "masque connection ended");
                }
            });
        }

        Ok(())
    }
}

/// Drive one HTTP/3 connection: spawn the connection-wide datagram reader, then
/// accept `CONNECT-UDP` / `CONNECT-IP` requests, validating and tunnelling each.
async fn handle_connection(
    mut h3_conn: H3Conn,
    peer: SocketAddr,
    quinn_conn: QuinnConnection,
    resolver: Resolver,
    config: AppConfig,
    // CONNECT-IP address pool; unused off-Linux (connect-ip is answered 501).
    #[cfg(target_os = "linux")] pool: Arc<StdMutex<IpPool>>,
    #[cfg(not(target_os = "linux"))] _pool: (),
) -> anyhow::Result<()> {
    let routes: Routes = Arc::new(Mutex::new(HashMap::new()));

    // One reader for the whole connection. It owns its own quinn::Connection
    // clone, so it does not borrow `h3_conn`. It demultiplexes incoming
    // datagrams (Quarter Stream ID already stripped by h3-datagram; Context ID
    // still present) to the right tunnel task by QUIC stream id.
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
                        // The tunnel task owns the UDP socket / tun device;
                        // just forward the raw datagram payload (QSID already
                        // stripped by h3-datagram; the tunnel parses the
                        // Context ID itself).
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
        let (req, mut req_stream) = match resolver_req.resolve_request().await {
            Ok(v) => v,
            Err(e) => {
                warn!(peer = %peer, error = %e, "failed to resolve CONNECT-UDP request");
                continue;
            }
        };
        let stream_id = req_stream.id();

        // Classify the request up front so we only wire up the datagram/route
        // plumbing that the chosen protocol actually uses. `req.extensions()` is
        // only borrowed here, and both `req` and `req_stream` are moved into
        // exactly one arm below.
        let proto = req.extensions().get::<Protocol>().cloned();
        let is_connect = *req.method() == Method::CONNECT;
        // The wire string of the extended-CONNECT `:protocol`, if any. Used to
        // discriminate protocols h3 0.0.8 upstream could not surface (connect-ip,
        // websocket, ...) — they now arrive as `Protocol::Other(...)` and we route
        // on their `as_str()` value.
        let proto_str = proto.as_ref().map(|p| p.as_str());

        if !is_connect {
            // HTTP/3 request streams carry CONNECT (plain or extended). A
            // non-CONNECT request is unsupported -> 405.
            tokio::spawn(async move {
                let _ = send_status(&mut req_stream, StatusCode::METHOD_NOT_ALLOWED).await;
            });
            continue;
        } else if proto == Some(Protocol::CONNECT_UDP) {
            // Owned sender for this stream (holds its own quinn::Connection
            // clone). Register it so the connection-wide datagram reader can
            // demultiplex capsules to this tunnel.
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
        } else if proto_str == Some("connect-ip") || (proto.is_none() && is_connect_ip_path(req.uri().path())) {
            // CONNECT-IP (RFC 9484). With the patched h3, a real client sends
            // `:protocol = connect-ip`; we also still accept the legacy
            // path-only form (no `:protocol`) on the RFC 9484 default path.
            // The tun/NAT data plane is Linux-only; on other platforms the
            // request fails cleanly (501) and the other protocols are served.
            #[cfg(target_os = "linux")]
            {
                let sender: H3Sender = h3_conn.get_datagram_sender(stream_id);
                let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                routes.lock().await.insert(stream_id, tx);

                let config = config.clone();
                let quinn_conn = quinn_conn.clone();
                let routes = routes.clone();
                let pool = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_ip_stream(
                        req,
                        req_stream,
                        sender,
                        rx,
                        config,
                        peer,
                        stream_id,
                        quinn_conn,
                        pool,
                    )
                    .await
                    {
                        debug!(peer = %peer, stream = %stream_id, error = %e, "CONNECT-IP tunnel ended");
                    }
                    routes.lock().await.remove(&stream_id);
                });
            }
            #[cfg(not(target_os = "linux"))]
            {
                warn!(
                    peer = %peer,
                    stream = %stream_id,
                    "CONNECT-IP requires Linux (no tun/NAT data plane on this platform) -> 501"
                );
                tokio::spawn(async move {
                    let _ = send_status(&mut req_stream, StatusCode::NOT_IMPLEMENTED).await;
                });
            }
        } else if proto_str == Some("websocket") {
            // RFC 9220 (WebSocket over HTTP/3): extended CONNECT with
            // `:protocol = websocket`. After a `200`, the stream carries the
            // WebSocket handshake + frames as the tunnel body — the proxy does
            // NOT interpret WebSocket; it is a byte pipe to the origin (target =
            // `:authority`), identical to a plain TCP CONNECT. Upgrade headers are
            // simply forwarded inside the tunnel.
            let resolver = resolver.clone();
            let config = config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_websocket_connect_stream(
                    req,
                    req_stream,
                    resolver,
                    config,
                    peer,
                    stream_id,
                )
                .await
                {
                    debug!(peer = %peer, stream = %stream_id, error = %e, "CONNECT (WebSocket) tunnel ended");
                }
            });
        } else if proto.is_none() {
            // Plain TCP CONNECT (RFC 9114 §4.4): an extended CONNECT whose
            // `:protocol` is absent, not on the connect-ip path. A pure byte pipe
            // to the `:authority` target — no datagrams, no capsules, no tun.
            let resolver = resolver.clone();
            let config = config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_tcp_connect_stream(
                    req,
                    req_stream,
                    resolver,
                    config,
                    peer,
                    stream_id,
                )
                .await
                {
                    debug!(peer = %peer, stream = %stream_id, error = %e, "CONNECT (TCP) tunnel ended");
                }
            });
        } else {
            // An extended CONNECT with a `:protocol` we do not tunnel
            // (today: `webtransport`). With the patched h3, connect-ip and
            // websocket reach their own arms above; anything else is 501.
            warn!(
                peer = %peer,
                stream = %stream_id,
                protocol = ?proto,
                "unsupported extended CONNECT :protocol; h3 0.0.8 cannot tunnel this -> 501"
            );
            tokio::spawn(async move {
                let _ = send_status(&mut req_stream, StatusCode::NOT_IMPLEMENTED).await;
            });
            continue;
        }
    }

    // Accept loop ended (connection closed). Clear the routing table so any
    // tunnel tasks still awaiting `rx.recv()` observe `None` and terminate
    // rather than leaking until the process exits.
    routes.lock().await.clear();

    Ok(())
}

/// Tunnel one `CONNECT-UDP` request: validate, resolve target once, then relay
/// UDP packets <-> HTTP/3 DATAGRAMs (Context ID 0 + raw UDP payload) for the
/// lifetime of the stream.
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

    // 1:1 tunnel to the single target named by the :path. Bind a UDP socket of
    // the same address family and connect() it so recv/send are with the target
    // only.
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
            // Downlink: target -> client (Context ID 0 + raw UDP payload, sent
            // via HTTP/3 DATAGRAM; h3-datagram adds the Quarter Stream ID).
            read = udp.recv_from(&mut buf) => {
                let (n, _from) = match read {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(peer = %peer, target = %target, error = %e, "tunnel UDP recv failed");
                        break;
                    }
                };
                // RFC 9298 §4.2: HTTP Datagram payload = Context ID (varint) +
                // UDP Proxying Payload. Context ID 0 is a single 0x00 byte.
                let mut dgram = BytesMut::with_capacity(1 + n);
                dgram.put_u8(0x00);
                dgram.extend_from_slice(&buf[..n]);
                let dgram = dgram.freeze();

                // QUIC datagrams are MTU-bounded (~1200 B initially). A UDP
                // packet that won't fit is dropped; RFC 9298 relies on the
                // client's own retransmission. (h3-datagram's SendDatagramError
                // variants are private in 0.0.2, so we pre-check the MTU
                // instead of matching TooLarge at runtime.)
                let too_big = match quinn_conn.max_datagram_size() {
                    Some(max) => dgram.len() + DATAGRAM_OVERHEAD > max,
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

                if let Err(e) = sender.send_datagram(dgram) {
                    debug!(peer = %peer, error = %e, "datagram send error; ending tunnel");
                    break;
                }
            }
            // Uplink: client -> target. Reader handed us the datagram payload
            // (QSID already stripped); parse the Context ID and require 0 —
            // the remainder is then the raw UDP payload.
            got = rx.recv() => {
                match got {
                    Some(dgram) => match capsule::strip_context_id(&dgram) {
                        Some(payload) => {
                            if let Err(e) = udp.send(payload).await {
                                debug!(peer = %peer, target = %target, error = %e, "tunnel UDP send failed");
                            }
                        }
                        // Non-zero/truncated Context ID: drop silently, keep
                        // the tunnel up (RFC 9298 §4.2).
                        None => debug!(peer = %peer, stream = %stream_id, "datagram with non-zero or truncated Context ID dropped"),
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

/// Tunnel one `CONNECT-IP` request: a real layer-3 VPN gateway.
///
/// After the `200` + `capsule-protocol` response, this allocates the client an
/// address from the shared pool, creates a `tun` device (proxy side = one end of
/// a PtP link, client = the peer), NATs the client's traffic, and then relays
/// IP packets between the `tun` device and HTTP/3 DATAGRAMs (Context ID 0 +
/// raw packet) for the life of the stream. Signalling is on the request
/// stream: the proxy sends `ADDRESS_ASSIGN` (assigned client address/prefix)
/// and `ROUTE_ADVERTISEMENT` (default route) as RFC 9297 capsules via
/// `send_data`, and a stream-reader task decodes client capsules
/// (`ADDRESS_REQUEST` is answered with a matching `ADDRESS_ASSIGN`).
/// On teardown, dropping `tun` removes the interface, the iptables rules, and
/// restores `ip_forward`.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn handle_ip_stream<S>(
    req: Request<()>,
    mut req_stream: RequestStream<S, Bytes>,
    mut sender: H3Sender,
    mut rx: Rx,
    config: AppConfig,
    peer: SocketAddr,
    stream_id: StreamId,
    quinn_conn: QuinnConnection,
    pool: Arc<StdMutex<IpPool>>,
) -> anyhow::Result<()>
where
    S: quic::SendStream<Bytes> + quic::RecvStream + quic::BidiStream<Bytes>,
    // The request stream is split and its halves move into the spawned
    // capsule-reader task, so the associated stream types must be `Send`.
    <S as quic::BidiStream<Bytes>>::SendStream: Send + 'static,
    <S as quic::BidiStream<Bytes>>::RecvStream: Send + 'static,
{
    let token = config.auth_token.as_deref();

    if let Err(status) = validate_connect_ip(&req, token) {
        send_status(&mut req_stream, status).await?;
        return Ok(());
    }

    // Allocate this session's (proxy, client, prefix) from the shared pool.
    // Compute the allocation first and drop the std MutexGuard before any await
    // (a guard held across an await would make this task non-`Send`).
    let alloc = {
        let mut pool = pool.lock().unwrap();
        pool.allocate()
    };
    let (proxy_addr, client_addr, prefix) = match alloc {
        Ok(v) => v,
        Err(e) => {
            warn!(peer = %peer, error = %e, "CONNECT-IP address pool exhausted");
            send_status(&mut req_stream, StatusCode::SERVICE_UNAVAILABLE).await?;
            anyhow::bail!("ip pool exhausted: {e}");
        }
    };

    // Size the tun MTU to fit inside a QUIC DATAGRAM (capsule + IP header
    // overhead), so we rarely have to drop packets that exceed the datagram MTU.
    let mtu = quinn_conn
        .max_datagram_size()
        .map(|max| max.saturating_sub(DATAGRAM_OVERHEAD + 40));
    let mtu = mtu.filter(|m| *m > 0);

    // Create the `tun` device + routing + NAT. Requires root (CAP_NET_ADMIN).
    let tun = match TunDevice::create("auto%d", proxy_addr, client_addr, prefix, mtu) {
        Ok(t) => t,
        Err(e) => {
            warn!(peer = %peer, client = %client_addr, error = %e, "failed to create tun device");
            send_status(&mut req_stream, StatusCode::INTERNAL_SERVER_ERROR).await?;
            anyhow::bail!("tun setup failed: {e}");
        }
    };
    info!(
        peer = %peer,
        tun = %tun.name(),
        proxy = %proxy_addr,
        client = %client_addr,
        prefix,
        "CONNECT-IP tunnel established"
    );

    // 200 + Capsule-Protocol: ?1, empty body. Keep the control stream OPEN.
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("capsule-protocol", "?1")
        .body(())
        .expect("valid 200 response");
    req_stream.send_response(resp).await?;

    // Signalling capsules travel on the CONNECT request stream (RFC 9297 §5
    // framing: Type + Length + Value), NOT in datagrams (RFC 9484 §4.7):
    // tell the client the address/prefix it owns...
    let assign = capsule::encode_address_assign(&[capsule::AssignedAddress {
        request_id: 0,
        address: client_addr,
        prefix_len: prefix,
    }]);
    if let Err(e) = req_stream.send_data(assign).await {
        debug!(peer = %peer, error = %e, "failed to send ADDRESS_ASSIGN capsule");
        let _ = req_stream.finish().await;
        return Ok(());
    }

    // ...and advertise a default route so the client sends all traffic through us.
    let route_adv = capsule::encode_route_advertisement(&[default_route_range(client_addr)]);
    if let Err(e) = req_stream.send_data(route_adv).await {
        debug!(peer = %peer, error = %e, "failed to send ROUTE_ADVERTISEMENT capsule");
        let _ = req_stream.finish().await;
        return Ok(());
    }

    // Split the request stream: the send half answers client ADDRESS_REQUEST
    // capsules and finishes the stream at EOF; the recv half is decoded as an
    // RFC 9297 capsule sequence by a dedicated reader task.
    let (mut sig_send, mut sig_recv) = req_stream.split();

    // Resolved when the capsule reader sees the stream EOF/error — that is the
    // tunnel teardown signal (the control stream is the tunnel's lifetime).
    let (teardown_tx, mut teardown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut pending = BytesMut::new();
        'reader: loop {
            match sig_recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    pending.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                    // Bound memory on a malicious/garbled stream: RFC 9484
                    // capsules we care about are tiny.
                    if pending.len() > 1_048_576 {
                        debug!(peer = %peer, "CONNECT-IP capsule buffer exceeded 1 MiB; aborting stream");
                        break 'reader;
                    }
                    while let Some((typ, value, used)) = capsule::split_capsule(&pending) {
                        let value = value.to_vec();
                        let _ = pending.split_to(used);
                        match typ {
                            capsule::CAPSULE_ADDRESS_REQUEST => {
                                match capsule::decode_address_value(&value) {
                                    // RFC 9484 §4.7.2: a zero-entry
                                    // ADDRESS_REQUEST must abort the stream.
                                    Some(entries) if entries.is_empty() => {
                                        debug!(peer = %peer, "client sent empty ADDRESS_REQUEST; aborting");
                                        break 'reader;
                                    }
                                    Some(entries) => {
                                        debug!(
                                            peer = %peer,
                                            requested = ?entries,
                                            "client ADDRESS_REQUEST; responding with ADDRESS_ASSIGN"
                                        );
                                        // We always assign the same single
                                        // pool address, so answer every
                                        // Request ID with that assignment
                                        // (matching Request ID per §4.7.2).
                                        let replies: Vec<capsule::AssignedAddress> = entries
                                            .iter()
                                            .map(|r| capsule::AssignedAddress {
                                                request_id: r.request_id,
                                                address: client_addr,
                                                prefix_len: prefix,
                                            })
                                            .collect();
                                        let reply =
                                            capsule::encode_address_assign(&replies);
                                        if sig_send.send_data(reply).await.is_err() {
                                            break 'reader;
                                        }
                                    }
                                    None => {
                                        // Malformed capsule: RFC 9484 §4.7.2
                                        // defers to RFC 9297 §3.3 error
                                        // handling — abort the request stream.
                                        debug!(peer = %peer, "malformed ADDRESS_REQUEST; aborting");
                                        break 'reader;
                                    }
                                }
                            }
                            capsule::CAPSULE_ROUTE_ADVERTISEMENT => {
                                // The client advertises the route(s) it wants
                                // us to carry. We ignore the content (we
                                // always advertise a default route) but parse
                                // it for observability.
                                match capsule::decode_route_value(&value) {
                                    Some(routes) => {
                                        debug!(peer = %peer, routes = ?routes, "client ROUTE_ADVERTISEMENT")
                                    }
                                    None => debug!(peer = %peer, "malformed client ROUTE_ADVERTISEMENT ignored"),
                                }
                            }
                            // ADDRESS_ASSIGN and anything else: accept and
                            // ignore gracefully.
                            _ => debug!(peer = %peer, type_ = typ, "ignoring unknown CONNECT-IP capsule"),
                        }
                    }
                }
                Ok(None) => break 'reader, // client finished the stream
                Err(e) => {
                    debug!(peer = %peer, error = %e, "CONNECT-IP capsule stream errored");
                    break 'reader;
                }
            }
        }
        // Stream EOF/error: signal tunnel teardown, then close the stream.
        let _ = teardown_tx.send(());
        let _ = sig_send.finish().await;
    });

    // Data plane: tun <-> HTTP/3 DATAGRAMs (Context ID 0 + raw IP packet).
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            read = tun.read_packet(&mut buf) => {
                match read {
                    Ok(n) if n > 0 => {
                        // RFC 9484 §4.2: HTTP Datagram payload = Context ID
                        // (varint) + IP packet. Context ID 0 = single 0x00 byte.
                        let mut dgram = BytesMut::with_capacity(1 + n);
                        dgram.put_u8(0x00);
                        dgram.extend_from_slice(&buf[..n]);
                        let dgram = dgram.freeze();
                        let too_big = match quinn_conn.max_datagram_size() {
                            Some(max) => dgram.len() + DATAGRAM_OVERHEAD > max,
                            None => true,
                        };
                        if too_big {
                            debug!(
                                peer = %peer,
                                len = n,
                                "IP packet too large for QUIC datagram; dropping"
                            );
                            continue;
                        }
                        if let Err(e) = sender.send_datagram(dgram) {
                            debug!(peer = %peer, error = %e, "datagram send error; ending tunnel");
                            break;
                        }
                    }
                    Ok(_) => continue, // 0-byte read; keep waiting
                    Err(e) => {
                        debug!(peer = %peer, error = %e, "tun read failed; ending tunnel");
                        break;
                    }
                }
            }
            got = rx.recv() => {
                match got {
                    Some(dgram) => match capsule::strip_context_id(&dgram) {
                        // Context ID 0: the remainder is the raw IP packet.
                        // Inject it into the tun device; the kernel routes it
                        // onward (and NAT rewrites it for egress).
                        Some(pkt) => {
                            if let Err(e) = tun.write_packet(pkt).await {
                                debug!(peer = %peer, error = %e, "tun write failed");
                            }
                        }
                        // Non-zero/truncated Context ID: drop silently, keep
                        // the tunnel up (RFC 9484 §4.2).
                        None => debug!(peer = %peer, stream = %stream_id, "datagram with non-zero or truncated Context ID dropped"),
                    },
                    None => break, // reader task gone / connection closed
                }
            }
            _ = &mut teardown_rx => {
                // Control stream ended (client closed it, or the capsule
                // reader aborted): the tunnel is over.
                debug!(peer = %peer, stream = %stream_id, "CONNECT-IP control stream ended; tearing down");
                break;
            }
        }
    }

    // Teardown: `tun` is dropped here, which removes the interface, the
    // iptables rules, and restores `ip_forward`. The capsule reader task owns
    // the request stream halves and finishes the stream when it observes EOF.
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

/// Whether a request path is the RFC 9484 `connect-ip` default URI template
/// (`/.well-known/masque/ip/`, with or without a trailing slash). Disjoint from
/// CONNECT-UDP's `/.well-known/masque/udp/...`.
fn is_connect_ip_path(path: &str) -> bool {
    path == MASQUE_IP_PATH || path.starts_with("/.well-known/masque/ip/")
}

/// Validate a `CONNECT-IP` request (RFC 9484). Returns `Ok(())` if the request
/// is well-formed and authorized, or the HTTP status to respond with otherwise.
///
/// The `:protocol` check is deliberately via the path, not the `:protocol`
/// extension: h3 0.0.8 cannot parse `connect-ip` as a `:protocol` at all (see
/// `MASQUE_IP_PATH`), so once h3 learns it, the path is still a valid
/// discriminator and a stray `connect-udp` on this path is rejected below.
#[cfg(target_os = "linux")]
fn validate_connect_ip(req: &Request<()>, token: Option<&str>) -> Result<(), StatusCode> {
    if req.method() != Method::CONNECT {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    if !is_connect_ip_path(req.uri().path()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    // A CONNECT-UDP request must not be served on the connect-ip path.
    if req.extensions().get::<Protocol>() == Some(&Protocol::CONNECT_UDP) {
        return Err(StatusCode::NOT_IMPLEMENTED);
    }
    if req
        .headers()
        .get("capsule-protocol")
        .map(|v| v.as_bytes())
        != Some(b"?1")
    {
        // RFC 9484 requires the Capsule-Protocol indicator.
        return Err(StatusCode::BAD_REQUEST);
    }
    if !check_proxy_auth(req.headers(), token) {
        return Err(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    }
    Ok(())
}

/// Validate a **plain TCP** CONNECT (RFC 9114 §4.4 — an extended CONNECT with no
/// `:protocol` extension). Returns the resolved `(host, port)` target on success,
/// or the HTTP status code to respond with on failure.
///
/// Unlike `CONNECT-UDP`/`CONNECT-IP`, the target is the request's `:authority`
/// (`host:port`) — exactly like an HTTP/1.1 `CONNECT`. An explicit port is
/// required; a missing port is rejected with `400` (RFC 9114 CONNECT forbids an
/// omitted port). Reuses the shared `parse_authority` / `check_proxy_auth` /
/// `Host` logic from the TCP proxy's `handle_http_connect`.
fn validate_tcp_connect(req: &Request<()>, token: Option<&str>) -> Result<(Host, u16), StatusCode> {
    if *req.method() != Method::CONNECT {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    // A plain TCP CONNECT carries NO `:protocol` extension. An extended CONNECT
    // that *does* carry one (connect-udp, webtransport, websocket, connect-ip)
    // is handled by a different branch of the dispatcher and must never reach
    // the plain TCP tunnel path.
    if req.extensions().get::<Protocol>().is_some() {
        return Err(StatusCode::NOT_IMPLEMENTED);
    }
    if !check_proxy_auth(req.headers(), token) {
        return Err(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    }
    // Target = `:authority` (host:port). An explicit port is required.
    let authority = req.uri().authority().map(|a| a.as_str()).unwrap_or("");
    parse_authority(authority).map_err(|_| StatusCode::BAD_REQUEST)
}

/// Tunnel one **plain TCP** CONNECT (RFC 9114 §4.4 — an extended CONNECT whose
/// `:protocol` is absent) over HTTP/3.
///
/// After a `2xx` response with an empty body (the control stream is kept open
/// for the tunnel's lifetime), bytes are piped bidirectionally between the client
/// and the upstream `TcpStream`:
///
/// * **client → target:** `RequestStream::recv_data()` → `TcpStream::write`.
/// * **target → client:** `TcpStream::read` → `RequestStream::send_data(...)`.
///   The client send side is `finish()`ed only once the upstream closes, which
///   signals end-of-stream to the client (RFC 9114 §4.4).
///
/// This is a pure TCP byte pipe — no capsules, no DATAGRAMs, no tun device. Much
/// simpler than `CONNECT-UDP`/`CONNECT-IP`, which is the whole point of plain
/// CONNECT over HTTP/3.
/// Validate an **RFC 9220 WebSocket-over-HTTP/3** extended CONNECT
/// (`:protocol = websocket`). Target is the request's `:authority`
/// (`host:port`), like a plain TCP CONNECT. The proxy does not interpret
/// WebSocket — it is a byte pipe, so the only additional check beyond auth +
/// target parsing is that the `:protocol` really is `websocket`.
fn validate_websocket_connect(req: &Request<()>, token: Option<&str>) -> Result<(Host, u16), StatusCode> {
    if *req.method() != Method::CONNECT {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    if req.extensions().get::<Protocol>().map(|p| p.as_str()) != Some("websocket") {
        // Not an RFC 9220 WebSocket extended CONNECT -> not ours to serve.
        return Err(StatusCode::NOT_IMPLEMENTED);
    }
    if !check_proxy_auth(req.headers(), token) {
        return Err(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    }
    // Target = `:authority` (host:port). An explicit port is required.
    let authority = req.uri().authority().map(|a| a.as_str()).unwrap_or("");
    parse_authority(authority).map_err(|_| StatusCode::BAD_REQUEST)
}

/// Tunnel one **plain TCP** CONNECT (RFC 9114 §4.4 — an extended CONNECT whose
/// `:protocol` is absent) over HTTP/3. See `tcp_connect_tunnel` for the pipe.
async fn handle_tcp_connect_stream<S>(
    req: Request<()>,
    req_stream: RequestStream<S, Bytes>,
    resolver: Resolver,
    config: AppConfig,
    peer: SocketAddr,
    stream_id: StreamId,
) -> anyhow::Result<()>
where
    S: quic::SendStream<Bytes> + quic::RecvStream + quic::BidiStream<Bytes>,
{
    let token = config.auth_token.as_deref();
    let (host, port) = match validate_tcp_connect(&req, token) {
        Ok(target) => target,
        Err(status) => {
            let mut req_stream = req_stream;
            send_status(&mut req_stream, status).await?;
            return Ok(());
        }
    };
    tcp_connect_tunnel(req_stream, host, port, resolver, config, peer, stream_id, "tcp").await
}

/// Tunnel one **RFC 9220 WebSocket-over-HTTP/3** extended CONNECT. After the
/// `200`, the stream carries the WebSocket handshake + frames as the tunnel
/// body — a pure byte pipe to the `:authority` origin, identical to a plain
/// TCP CONNECT (the proxy does not interpret WebSocket; upgrade headers are
/// simply forwarded).
async fn handle_websocket_connect_stream<S>(
    req: Request<()>,
    req_stream: RequestStream<S, Bytes>,
    resolver: Resolver,
    config: AppConfig,
    peer: SocketAddr,
    stream_id: StreamId,
) -> anyhow::Result<()>
where
    S: quic::SendStream<Bytes> + quic::RecvStream + quic::BidiStream<Bytes>,
{
    let token = config.auth_token.as_deref();
    let (host, port) = match validate_websocket_connect(&req, token) {
        Ok(target) => target,
        Err(status) => {
            let mut req_stream = req_stream;
            send_status(&mut req_stream, status).await?;
            return Ok(());
        }
    };
    tcp_connect_tunnel(req_stream, host, port, resolver, config, peer, stream_id, "ws").await
}

/// Shared bidirectional byte pipe for the TCP-family HTTP/3 CONNECT tunnels
/// (plain TCP CONNECT per RFC 9114 and RFC 9220 WebSocket-over-H3). Validates
/// auth + target upstream; the only difference between the two callers is the
/// `transport` flow-log tag.
#[allow(clippy::too_many_arguments)]
async fn tcp_connect_tunnel<S>(
    mut req_stream: RequestStream<S, Bytes>,
    host: Host,
    port: u16,
    resolver: Resolver,
    config: AppConfig,
    peer: SocketAddr,
    stream_id: StreamId,
    transport: &str,
) -> anyhow::Result<()>
where
    S: quic::SendStream<Bytes> + quic::RecvStream + quic::BidiStream<Bytes>,
{
    let target = host.resolve(&resolver, port).await?;
    if config.block_special_addrs() && is_rfc6890_special(target.ip()) {
        warn!(
            peer = %peer,
            target = %target,
            "rejecting CONNECT (TCP) to RFC 6890 special-purpose address"
        );
        send_status(&mut req_stream, StatusCode::FORBIDDEN).await?;
        anyhow::bail!("CONNECT (TCP) target {target} is a special-purpose (RFC 6890) address");
    }

    // Flow log — identical shape to `handle_http_connect` ("tcp"/"ws" transport,
    // "masque-connect" proxy tag) so the TCP tunnels are greppable together.
    log_request(peer, &host, port, transport, target, "masque-connect");

    debug!(peer = %peer, stream = %stream_id, target = %target, "CONNECT (TCP) tunnel opened");

    let connect_result = timeout(config.connect_timeout(), TcpStream::connect(target))
        .await
        .with_context(|| format!("CONNECT (TCP) upstream connect to {target} timed out"))?;
    let upstream = match connect_result {
        Ok(stream) => stream,
        Err(e) => {
            warn!(peer = %peer, target = %target, error = %e, "CONNECT (TCP) upstream connect failed");
            send_status(&mut req_stream, StatusCode::BAD_GATEWAY).await?;
            return Err(e).context("CONNECT (TCP) upstream connect failed");
        }
    };

    // 2xx with an EMPTY body. Do NOT `finish()` here — the control stream stays
    // open for the tunnel and is finished only when the upstream half closes.
    let resp = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .expect("valid 200 response");
    req_stream.send_response(resp).await?;

    // Split the h3 request stream into independent send/recv halves so the two
    // directions can be pumped concurrently on one task. `split` requires the
    // underlying QUIC stream to be bidirectional, which a CONNECT request stream
    // is (RFC 9114 uses a client-initiated bidirectional stream).
    let (mut client_send, mut client_recv) = req_stream.split();
    let (mut up_read, mut up_write) = tokio::io::split(upstream);

    // Direction 1: client -> target.
    let to_target = async {
        loop {
            match client_recv.recv_data().await {
                Ok(Some(mut buf)) => {
                    let data = buf.copy_to_bytes(buf.remaining());
                    if up_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    // Client finished sending; half-close the upstream write so
                    // the target observes EOF.
                    let _ = up_write.shutdown().await;
                    break;
                }
                Err(_) => break,
            }
        }
    };

    // Direction 2: target -> client.
    let to_client = async {
        let mut buf = vec![0u8; 16384];
        loop {
            match up_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if client_send
                        .send_data(Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // Upstream closed: signal end-of-stream to the client and close the
        // control stream cleanly.
        let _ = client_send.finish().await;
    };

    // Close the tunnel when both directions end (or either errors).
    tokio::join!(to_target, to_client);
    Ok(())
}

/// The default-route `ROUTE_ADVERTISEMENT` range for the family of `addr`
/// (RFC 9484 §4.7.3): `0.0.0.0–255.255.255.255` / `::–ffff:…:ffff`, all
/// protocols (`ip_protocol = 0`).
#[cfg(target_os = "linux")]
fn default_route_range(addr: IpAddr) -> capsule::IpRange {
    match addr {
        IpAddr::V4(_) => capsule::IpRange {
            start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            end: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            ip_protocol: 0,
        },
        IpAddr::V6(_) => capsule::IpRange {
            start: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            end: IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            )),
            ip_protocol: 0,
        },
    }
}

/// Extract the CONNECT-UDP target from the request's `:path` (RFC 9298 §3.4).
///
/// RFC 9298 puts the UDP target in the **path**, not in `:authority`: `:authority`
/// is the *proxy's* own authority, and `:path` is the expansion of the URI
/// template. The normative example (RFC 9298 Figure 5) is:
///
/// ```text
/// :path = /.well-known/masque/udp/192.0.2.6/443/
/// :authority = example.org
/// ```
///
/// We implement only the default (IANA-registered) template from RFC 9298 §2:
/// `https://$PROXY_HOST:$PROXY_PORT/.well-known/masque/udp/{target_host}/{target_port}/`
///
/// The obsolete `draft-schinazi-masque-connect-udp-00` encoding (target in
/// `:authority`) is deliberately **not** accepted as a fallback: no known client
/// sends it, and honouring it would tunnel to the proxy itself.
///
/// NOTE on `:authority`: it is intentionally unused here. It identifies *us*,
/// not the target, but this server has no config for its own public authority
/// (the QUIC bind address is not necessarily the name clients connect to), so we
/// do not try to match it. We simply must not mistake it for the target.
fn parse_target(req: &Request<()>) -> Option<(Host, u16)> {
    // Everything after the fixed prefix is `{target_host}/{target_port}` plus
    // an optional trailing `/`. `splitn(3, '/')` keeps any trailing empty
    // segment (and any junk after it) out of the two fields we read.
    let rest = req.uri().path().strip_prefix(MASQUE_UDP_PATH_PREFIX)?;
    let mut segments = rest.splitn(3, '/');
    let host_seg = segments.next()?;
    let port_seg = segments.next()?;

    // A missing or empty segment means no target / no explicit port; RFC 9298
    // forbids an omitted port, so reject rather than defaulting to 443.
    if host_seg.is_empty() || port_seg.is_empty() {
        return None;
    }
    let port: u16 = port_seg.parse().ok()?; // non-numeric port -> 400

    Some((parse_target_host(host_seg)?, port))
}

/// Decode one `{target_host}` path segment into a `Host`.
///
/// RFC 9298 §3.1 requires percent-decoding, so an IPv6 literal legitimately
/// arrives as `2001%3Adb8%3A%3A1`. Chromium *computes* that encoded form but
/// never sends it — real Chrome puts a bare `2001:db8::1` in the path — so raw
/// unencoded colons must be accepted too. Bracketed literals are tolerated and
/// unwrapped before `IpAddr` parsing.
fn parse_target_host(segment: &str) -> Option<Host> {
    let decoded = percent_encoding::percent_decode_str(segment)
        .decode_utf8()
        .ok()?;
    let host_str = match decoded.strip_prefix('[') {
        Some(inner) => inner.strip_suffix(']')?,
        None => &*decoded,
    };
    if host_str.is_empty() {
        return None;
    }
    Some(match host_str.parse::<IpAddr>() {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Name(host_str.to_string()),
    })
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
    use super::{
        check_proxy_auth, is_connect_ip_path, parse_target, validate_connect_ip,
        validate_tcp_connect, validate_connect_udp,
    };
    use base64::Engine;
    use crate::server::{Host, parse_authority};
    use h3::ext::Protocol;
    use http::{HeaderValue, Method, Request, Uri};
    use std::str::FromStr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Proxy authority used by the tests. Per RFC 9298 it is *our* address, not
    /// the target's.
    const PROXY: &str = "https://proxy.example.com:443";

    /// Build a default-template RFC 9298 `:path` for `host`/`port`.
    fn udp_path(host: &str, port: &str) -> String {
        format!("{PROXY}/.well-known/masque/udp/{host}/{port}/")
    }

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

    /// Build a RFC 9484 `connect-ip` request for the default URI template path.
    /// The `connect-ip` `:protocol` extension is NOT set here unless a test
    /// inserts one manually (the legacy path-based form). With the patched h3 a
    /// real client sends `:protocol = connect-ip`, which is surfaced as a
    /// `Protocol::Other` extension and routed by the dispatcher on its `as_str()`.
    fn connect_ip_request(uri: &str, with_capsule: bool, auth: Option<&str>) -> Request<()> {
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
        req
    }

    #[test]
    fn parse_target_domain_ipv4_and_ipv6() {
        // Domain target.
        let req = connect_udp_request(&udp_path("example.com", "8443"), true, None);
        let (host, port) = parse_target(&req).expect("parse domain");
        assert_eq!(host, Host::Name("example.com".to_string()));
        assert_eq!(port, 8443);

        // IPv4 target.
        let req4 = connect_udp_request(&udp_path("192.0.2.6", "443"), true, None);
        let (host, port) = parse_target(&req4).expect("parse v4");
        assert_eq!(host, Host::Ip("192.0.2.6".parse().unwrap()));
        assert_eq!(port, 443);

        // IPv6 target, percent-encoded as RFC 9298 §3.1 requires.
        let req6 = connect_udp_request(&udp_path("2001%3Adb8%3A%3A1", "443"), true, None);
        let (host, port) = parse_target(&req6).expect("parse encoded v6");
        assert_eq!(host, Host::Ip("2001:db8::1".parse().unwrap()));
        assert_eq!(port, 443);

        // IPv6 target with raw colons — Chromium computes the encoded form but
        // never sends it, so this is what real Chrome actually puts on the wire.
        let req6raw = connect_udp_request(&udp_path("2001:db8::1", "443"), true, None);
        let (host, port) = parse_target(&req6raw).expect("parse raw v6");
        assert_eq!(host, Host::Ip("2001:db8::1".parse().unwrap()));
        assert_eq!(port, 443);

        // Bracketed IPv6 literal is tolerated too.
        let req6b = connect_udp_request(&udp_path("[2001:db8::1]", "443"), true, None);
        let (host, port) = parse_target(&req6b).expect("parse bracketed v6");
        assert_eq!(host, Host::Ip("2001:db8::1".parse().unwrap()));
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_target_rejects_bad_prefix() {
        for bad in [
            "/.well-known/masque/udp",
            "/.well-known/masque/tcp/example.com/443/",
            "/masque/udp/example.com/443/",
            "/.well-known/masque/udpx/example.com/443/",
            "/",
            "",
        ] {
            let req = connect_udp_request(&format!("{PROXY}{bad}"), true, None);
            assert!(parse_target(&req).is_none(), "must reject prefix {bad}");
        }
    }

    #[test]
    fn parse_target_rejects_bad_or_missing_port() {
        // Non-numeric port.
        let bad = connect_udp_request(&udp_path("example.com", "https"), true, None);
        assert!(parse_target(&bad).is_none());

        // Out of range for u16.
        let big = connect_udp_request(&udp_path("example.com", "65536"), true, None);
        assert!(parse_target(&big).is_none());

        // Missing port segment entirely (path ends after the host).
        let missing = connect_udp_request(
            &format!("{PROXY}/.well-known/masque/udp/example.com"),
            true,
            None,
        );
        assert!(parse_target(&missing).is_none());

        // Empty port segment (host + trailing slash only).
        let empty = connect_udp_request(
            &format!("{PROXY}/.well-known/masque/udp/example.com/"),
            true,
            None,
        );
        assert!(parse_target(&empty).is_none());

        // Missing host segment.
        let no_host = connect_udp_request(&udp_path("", "443"), true, None);
        assert!(parse_target(&no_host).is_none());
    }

    #[test]
    fn parse_target_tolerates_trailing_slash_variants() {
        // Trailing slash present (the canonical template expansion) ...
        let with = connect_udp_request(
            &format!("{PROXY}/.well-known/masque/udp/example.com/8443/"),
            true,
            None,
        );
        assert_eq!(
            parse_target(&with).expect("parse with trailing slash"),
            (Host::Name("example.com".to_string()), 8443u16)
        );

        // ... and absent (some clients omit it).
        let without = connect_udp_request(
            &format!("{PROXY}/.well-known/masque/udp/example.com/8443"),
            true,
            None,
        );
        assert_eq!(
            parse_target(&without).expect("parse without trailing slash"),
            (Host::Name("example.com".to_string()), 8443u16)
        );
    }

    #[test]
    fn parse_target_ignores_authority() {
        // `:authority` is the *proxy's* identity (RFC 9298 §3.4), so a request
        // whose authority happens to look like a valid host:port must still
        // resolve to the target named by the path — not to the authority.
        let req = connect_udp_request(
            "https://192.0.2.6:443/.well-known/masque/udp/example.com/8443/",
            true,
            None,
        );
        let (host, port) = parse_target(&req).expect("parse");
        assert_eq!(host, Host::Name("example.com".to_string()));
        assert_eq!(port, 8443);

        // And the obsolete draft-00 form (target in `:authority`, no path) is
        // rejected outright rather than tunnelling to the proxy itself.
        let legacy = connect_udp_request("https://example.com:8443/", true, None);
        assert!(parse_target(&legacy).is_none());
    }

    #[test]
    fn auth_header_accepts_bearer_and_basic() {
        let token = "s3cr3t";
        let uri = udp_path("example.com", "443");
        // Bearer
        let req = connect_udp_request(&uri, true, Some("Bearer s3cr3t"));
        assert!(check_proxy_auth(req.headers(), Some(token)));

        // Basic user:token
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("user:s3cr3t")
        );
        let req = connect_udp_request(&uri, true, Some(&basic));
        assert!(check_proxy_auth(req.headers(), Some(token)));

        // Basic with just the token as credential
        let basic2 = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("s3cr3t")
        );
        let req = connect_udp_request(&uri, true, Some(&basic2));
        assert!(check_proxy_auth(req.headers(), Some(token)));
    }

    #[test]
    fn auth_header_rejects_wrong_or_missing() {
        let token = "s3cr3t";
        let uri = udp_path("example.com", "443");
        // Wrong bearer
        let req = connect_udp_request(&uri, true, Some("Bearer wrong"));
        assert!(!check_proxy_auth(req.headers(), Some(token)));

        // Basic with wrong password
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("user:nope")
        );
        let req = connect_udp_request(&uri, true, Some(&basic));
        assert!(!check_proxy_auth(req.headers(), Some(token)));

        // Missing header
        let req = connect_udp_request(&uri, true, None);
        assert!(!check_proxy_auth(req.headers(), Some(token)));

        // No token configured at all
        let req = connect_udp_request(&uri, true, Some("Bearer x"));
        assert!(!check_proxy_auth(req.headers(), None));
    }

    #[test]
    fn validate_connect_udp_accepts_and_rejects() {
        let token = "s3cr3t";
        let uri = udp_path("example.com", "443");
        // Happy path
        let req = connect_udp_request(&uri, true, Some("Bearer s3cr3t"));
        let (host, port) = validate_connect_udp(&req, Some(token)).expect("ok");
        assert_eq!(host, Host::Name("example.com".to_string()));
        assert_eq!(port, 443);

        // Wrong method
        let mut bad = connect_udp_request(&uri, true, Some("Bearer s3cr3t"));
        *bad.method_mut() = Method::GET;
        assert_eq!(
            validate_connect_udp(&bad, Some(token)).unwrap_err(),
            http::StatusCode::METHOD_NOT_ALLOWED
        );

        // Missing capsule-protocol
        let no_cap = connect_udp_request(&uri, false, Some("Bearer s3cr3t"));
        assert_eq!(
            validate_connect_udp(&no_cap, Some(token)).unwrap_err(),
            http::StatusCode::BAD_REQUEST
        );

        // Malformed target path -> 400
        let bad_target = connect_udp_request(&udp_path("example.com", "http"), true, Some("Bearer s3cr3t"));
        assert_eq!(
            validate_connect_udp(&bad_target, Some(token)).unwrap_err(),
            http::StatusCode::BAD_REQUEST
        );

        // Missing auth
        let no_auth = connect_udp_request(&uri, true, None);
        assert_eq!(
            validate_connect_udp(&no_auth, Some(token)).unwrap_err(),
            http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
        );

        // Not extended-connect (no :protocol)
        let mut no_proto = connect_udp_request(&uri, true, Some("Bearer s3cr3t"));
        no_proto.extensions_mut().clear();
        assert_eq!(
            validate_connect_udp(&no_proto, Some(token)).unwrap_err(),
            http::StatusCode::NOT_IMPLEMENTED
        );
    }

    #[test]
    fn connect_ip_path_detection() {
        assert!(is_connect_ip_path("/.well-known/masque/ip/"));
        assert!(is_connect_ip_path("/.well-known/masque/ip"));
        assert!(is_connect_ip_path("/.well-known/masque/ip/foo"));
        assert!(!is_connect_ip_path("/.well-known/masque/udp/1.2.3.4/53/"));
        assert!(!is_connect_ip_path("/.well-known/masque/ipx/"));
    }

    #[test]
    fn validate_connect_ip_accepts_and_rejects() {
        let token = "s3cr3t";
        // RFC 9484 default template (no path variables).
        let uri = format!("{PROXY}/.well-known/masque/ip/");
        // Happy path.
        let req = connect_ip_request(&uri, true, Some("Bearer s3cr3t"));
        assert!(validate_connect_ip(&req, Some(token)).is_ok());

        // Wrong method.
        let mut bad = connect_ip_request(&uri, true, Some("Bearer s3cr3t"));
        *bad.method_mut() = Method::GET;
        assert_eq!(
            validate_connect_ip(&bad, Some(token)).unwrap_err(),
            http::StatusCode::METHOD_NOT_ALLOWED
        );

        // Missing capsule-protocol.
        let no_cap = connect_ip_request(&uri, false, Some("Bearer s3cr3t"));
        assert_eq!(
            validate_connect_ip(&no_cap, Some(token)).unwrap_err(),
            http::StatusCode::BAD_REQUEST
        );

        // Bad (non-ip) path.
        let bad_path = connect_ip_request(
            &format!("{PROXY}/.well-known/masque/udp/1.2.3.4/53/"),
            true,
            Some("Bearer s3cr3t"),
        );
        assert_eq!(
            validate_connect_ip(&bad_path, Some(token)).unwrap_err(),
            http::StatusCode::BAD_REQUEST
        );

        // Missing auth.
        let no_auth = connect_ip_request(&uri, true, None);
        assert_eq!(
            validate_connect_ip(&no_auth, Some(token)).unwrap_err(),
            http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
        );

        // Wrong auth token.
        let wrong_auth = connect_ip_request(&uri, true, Some("Bearer nope"));
        assert_eq!(
            validate_connect_ip(&wrong_auth, Some(token)).unwrap_err(),
            http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
        );

        // A CONNECT-UDP request must not be served on the connect-ip path.
        let mut udp_on_ip = connect_ip_request(&uri, true, Some("Bearer s3cr3t"));
        udp_on_ip.extensions_mut().insert(Protocol::CONNECT_UDP);
        assert_eq!(
            validate_connect_ip(&udp_on_ip, Some(token)).unwrap_err(),
            http::StatusCode::NOT_IMPLEMENTED
        );
    }

    /// Proof that the patched h3 no longer rejects the extended-CONNECT
    /// `:protocol` values this server needs (`connect-ip`, `websocket`). Upstream
    /// h3 0.0.8's `Protocol::from_str` returned `Err(InvalidProtocol)` for
    /// anything but `webtransport`/`connect-udp`, so clients were turned away with
    /// `H3_MESSAGE_ERROR` before our code ran. `as_str()` must round-trip the
    /// exact wire string for the new `Other` variant.
    #[test]
    fn h3_accepts_arbitrary_protocols_connect_ip_and_websocket() {
        // Now parseable (was Err before the patch).
        assert!(Protocol::from_str("connect-ip").is_ok());
        assert!(Protocol::from_str("websocket").is_ok());
        // Built-ins still parse.
        assert!(Protocol::from_str("webtransport").is_ok());
        assert!(Protocol::from_str("connect-udp").is_ok());

        // `as_str()` round-trips the original wire bytes for the `Other` variant.
        assert!(
            Protocol::from_str("connect-ip")
                .map(|p| p.as_str() == "connect-ip")
                .unwrap_or(false)
        );
        assert!(
            Protocol::from_str("websocket")
                .map(|p| p.as_str() == "websocket")
                .unwrap_or(false)
        );

        // Only an empty string is still rejected (defensive non-empty guard).
        assert!(Protocol::from_str("").is_err());
    }

    /// Proof that a real `connect-ip` extended CONNECT now reaches
    /// `validate_connect_ip` instead of being rejected by h3 at parse time. This
    /// is the verifiable evidence that CONNECT-IP is no longer blocked at the
    /// dependency layer: we build the request exactly as a patched-h3 client
    /// would (`:protocol = connect-ip` surfaced as a `Protocol` extension) and
    /// assert it passes validation.
    #[test]
    fn connect_ip_protocol_extension_reaches_validation() {
        let token = "s3cr3t";
        let uri = format!("{PROXY}/.well-known/masque/ip/");
        let mut req = connect_ip_request(&uri, true, Some("Bearer s3cr3t"));
        // Insert the `connect-ip` `:protocol` extension just as h3 now surfaces it.
        let proto = Protocol::from_str("connect-ip").expect("patched h3 accepts connect-ip");
        req.extensions_mut().insert(proto);
        assert!(
            validate_connect_ip(&req, Some(token)).is_ok(),
            "connect-ip extended CONNECT must reach validation, not be rejected by h3"
        );
    }

/// Build a plain **TCP** CONNECT request (no `:protocol`), targeting `authority`
/// (host:port) and carrying optional `Proxy-Authorization`.
fn tcp_connect_request(authority: &str, auth: Option<&str>) -> Request<()> {
    let uri = format!("https://{authority}/");
    let mut req = Request::builder()
        .method(Method::CONNECT)
        .uri(uri.parse::<Uri>().expect("valid test uri"))
        .body(())
        .expect("valid request");
    if let Some(a) = auth {
        req.headers_mut()
            .insert("proxy-authorization", HeaderValue::from_str(a).expect("valid auth header"));
    }
    // No `:protocol` extension -> plain TCP CONNECT.
    req
}

    #[test]
    fn validate_tcp_connect_accepts_plain_connect() {
        let token = "s3cr3t";
        // IPv4 target with explicit port.
        let req = tcp_connect_request("127.0.0.1:8443", Some("Bearer s3cr3t"));
        let (host, port) = validate_tcp_connect(&req, Some(token)).expect("plain TCP CONNECT ok");
        assert_eq!(host, Host::Ip("127.0.0.1".parse().unwrap()));
        assert_eq!(port, 8443);

        // Hostname target with explicit port.
        let req = tcp_connect_request("example.com:8443", Some("Bearer s3cr3t"));
        let (host, port) = validate_tcp_connect(&req, Some(token)).expect("plain TCP CONNECT ok");
        assert_eq!(host, Host::Name("example.com".to_string()));
        assert_eq!(port, 8443);
    }

#[test]
fn validate_tcp_connect_target_parsing_ipv4_ipv6_hostname() {
    // IPv6 literal (bracketed) with explicit port.
    let req = tcp_connect_request("[::1]:443", Some("Bearer s3cr3t"));
    let (host, port) = validate_tcp_connect(&req, Some("s3cr3t")).expect("ipv6 ok");
    assert_eq!(host, Host::Ip("::1".parse().unwrap()));
    assert_eq!(port, 443);

    // A bare IPv6 literal like `::1:443` is not a valid URI authority, so it can
    // never reach the validator through a real HTTP/3 request. The parser that
    // backs it does accept it (host = ::1, port = 443) via rsplit on ':', which
    // matches the existing CONNECT behaviour in server.rs. We exercise the
    // parser directly since the host:port form cannot be embedded in a Uri.
    let (host, port) = parse_authority("::1:443").expect("bare ipv6 accepted by parser");
    assert_eq!(host, Host::Ip("::1".parse().unwrap()));
    assert_eq!(port, 443);
}

#[test]
fn validate_tcp_connect_missing_port_rejected_400() {
    let token = "s3cr3t";
    // Authority with no `:port` -> RFC 9114 requires an explicit port.
    let req = tcp_connect_request("example.com", Some("Bearer s3cr3t"));
    assert_eq!(
        validate_tcp_connect(&req, Some(token)).unwrap_err(),
        http::StatusCode::BAD_REQUEST
    );

    // Authority with a non-numeric port.
    let bad = tcp_connect_request("example.com:https", Some("Bearer s3cr3t"));
    assert_eq!(
        validate_tcp_connect(&bad, Some(token)).unwrap_err(),
        http::StatusCode::BAD_REQUEST
    );
}

#[test]
fn validate_tcp_connect_bad_auth_rejected_407() {
    let token = "s3cr3t";
    // Missing auth header.
    let no_auth = tcp_connect_request("127.0.0.1:8443", None);
    assert_eq!(
        validate_tcp_connect(&no_auth, Some(token)).unwrap_err(),
        http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );

    // Wrong token.
    let wrong = tcp_connect_request("127.0.0.1:8443", Some("Bearer nope"));
    assert_eq!(
        validate_tcp_connect(&wrong, Some(token)).unwrap_err(),
        http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
}

#[test]
fn validate_tcp_connect_rejects_any_protocol() {
    let token = "s3cr3t";
    // An extended CONNECT with a `:protocol` MUST NOT be dispatched to the plain
    // TCP tunnel path: connect-udp and webtransport both return 501.
    let mut udp = tcp_connect_request("127.0.0.1:8443", Some("Bearer s3cr3t"));
    udp.extensions_mut().insert(Protocol::CONNECT_UDP);
    assert_eq!(
        validate_tcp_connect(&udp, Some(token)).unwrap_err(),
        http::StatusCode::NOT_IMPLEMENTED
    );

    let mut wt = tcp_connect_request("127.0.0.1:8443", Some("Bearer s3cr3t"));
    wt.extensions_mut().insert(Protocol::WEB_TRANSPORT);
    assert_eq!(
        validate_tcp_connect(&wt, Some(token)).unwrap_err(),
        http::StatusCode::NOT_IMPLEMENTED
    );

    // A non-CONNECT method is rejected with 405 even with no `:protocol`.
    let mut get = tcp_connect_request("127.0.0.1:8443", Some("Bearer s3cr3t"));
    *get.method_mut() = Method::GET;
    assert_eq!(
        validate_tcp_connect(&get, Some(token)).unwrap_err(),
        http::StatusCode::METHOD_NOT_ALLOWED
    );
}

#[test]
fn parse_authority_round_trips_for_tcp_connect() {
    // Exercise the shared `:authority` parser directly (the one the TCP tunnel
    // reuses from handle_http_connect) across IPv4/IPv6/hostname forms.
    let (h, p) = parse_authority("127.0.0.1:8080").expect("ipv4");
    assert_eq!(h, Host::Ip("127.0.0.1".parse().unwrap()));
    assert_eq!(p, 8080);

    let (h, p) = parse_authority("[::1]:443").expect("ipv6");
    assert_eq!(h, Host::Ip("::1".parse().unwrap()));
    assert_eq!(p, 443);

    let (h, p) = parse_authority("example.com:8443").expect("hostname");
    assert_eq!(h, Host::Name("example.com".to_string()));
    assert_eq!(p, 8443);

    assert!(parse_authority("example.com").is_err(), "missing port must fail");
    assert!(parse_authority("").is_err());
}

/// Isolation test for the bidirectional pump used by `handle_tcp_connect_stream`.
///
/// A full QUIC handshake is exercised by `e2e_tcp_connect_roundtrip`; here we run
/// the *exact two loop bodies* of the handler against in-memory `tokio::io::duplex`
/// pipes (no networking, no openssl) to prove the flow + half-close semantics in
/// isolation:
///
/// * bytes written on the client side round-trip through the echo target and come
///   back intact;
/// * when the client closes its send side, the upstream observes EOF (half-close);
/// * when the upstream closes, the client's read side observes EOF (the handler's
///   `finish()` on the h3 send half, modelled here by `shutdown()`).
#[tokio::test]
async fn tcp_connect_pipe_logic_round_trips_and_eof_closes() {
    use tokio::io::split as io_split;

    // `h3_*` stand in for the h3 request stream's recv/send halves; `up_*` stand
    // in for the upstream TcpStream. `tokio::io::duplex` gives a bidirectional
    // in-memory pipe for each side.
    let (h3_client, h3_srv) = tokio::io::duplex(8192);
    let (mut h3_recv, mut h3_send) = io_split(h3_srv);
    let (up_client, up_srv) = tokio::io::duplex(8192);
    let (mut up_recv, mut up_send) = io_split(up_srv);

    // Echo target: bounce everything it reads back, shut down on client EOF.
    let echo = tokio::spawn(async move {
        let mut up = up_client;
        let mut buf = vec![0u8; 16384];
        loop {
            match up.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if up.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = up.shutdown().await;
    });

    // Direction 1: client -> target (mirrors handle_tcp_connect_stream `to_target`).
    let to_target = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match h3_recv.read(&mut buf).await {
                Ok(0) => {
                    let _ = up_send.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if up_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Direction 2: target -> client (mirrors `to_client`; `finish()` on the h3
    // send half is modelled by `shutdown()`).
    let to_client = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match up_recv.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if h3_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = h3_send.shutdown().await;
    });

    // Client: send a payload, then close its send side (EOF), then read echo.
    let payload = b"plain-tcp-connect-pipe-roundtrip";
    let mut h3_client = h3_client;
    h3_client.write_all(payload).await.expect("client write");
    h3_client.shutdown().await.expect("client shutdown");

    let mut got = Vec::new();
    h3_client
        .read_to_end(&mut got)
        .await
        .expect("client read echoed bytes");

    assert_eq!(got, payload, "payload must round-trip intact through the tunnel");

    // All pumps should terminate cleanly after both sides close.
    assert!(to_target.await.is_ok());
    assert!(to_client.await.is_ok());
    assert!(echo.await.is_ok());
}

}

/// Real end-to-end test: drive the actual `MasqueServer` with a `quinn` + `h3`
/// client over a freshly generated self-signed certificate. The client opens a
/// `CONNECT-UDP` tunnel to a local UDP echo socket, then round-trips a UDP
/// payload through HTTP/3 DATAGRAMs (Context ID 0 + raw payload, per RFC 9298
/// §4.2). This exercises the two defects the bind-only smoke test cannot catch:
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
    use std::str::FromStr;
    use std::time::Duration;

    use anyhow::anyhow;
    use bytes::{Buf, Bytes};
    use clap::Parser;
    use http::{HeaderValue, Method, Request, StatusCode};
    use h3::ext::Protocol;
    use h3_datagram::datagram_handler::HandleDatagramsExt;
    use h3_quinn::Connection as H3QuinnConnection;
    use libc;
    use quinn::{ClientConfig, Endpoint, TransportConfig};
    use rustls::RootCertStore;
    use rustls::crypto::ring;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::mpsc;

    use crate::capsule;
    use crate::config::Cli;
    use super::MasqueServer;

    /// End-to-end CONNECT-IP test (RFC 9484). Requires root (`CAP_NET_ADMIN`):
    /// the server creates a real `tun` device. On a non-root host (uid != 0) it
    /// skips gracefully. With root it:
    ///
    ///   1. sends `CONNECT-IP` (`:protocol = connect-ip`, RFC 9484 default
    ///      path) and asserts `200` + `Capsule-Protocol: ?1`;
    ///   2. parses the RFC 9297 capsules from the **stream body** and asserts
    ///      an `ADDRESS_ASSIGN` (0x01) and a `ROUTE_ADVERTISEMENT` (0x03)
    ///      arrive with the RFC 9484 §4.7 layouts;
    ///   3. first sends a datagram with a non-zero Context ID (varint 42) and
    ///      verifies the tunnel survives;
    ///   4. sends an ICMP echo request to the proxy's tun address as
    ///      `Context ID 0 + raw IP packet` and expects the kernel's reply back
    ///      the same way — proving the raw datagram data plane end-to-end.
    ///
    /// The client here is deliberately written to RFC 9484 directly (hand-built
    /// bytes, no shared codec) so it verifies the *wire format*, not our own
    /// encoder round-tripping itself.
    #[tokio::test]
    #[ignore = "requires openssl + root (CAP_NET_ADMIN); run: cargo test -- --ignored e2e_connect_ip_roundtrip"]
    async fn e2e_connect_ip_roundtrip() -> anyhow::Result<()> {
        // With the patched h3, `connect-ip` now parses (was `Err` before), so we
        // no longer early-skip here — the ROOT gate below is the real guard.
        assert!(
            Protocol::from_str("connect-ip").is_ok(),
            "patched h3 must accept connect-ip"
        );
        // The server creates a real tun device, which requires root. Skip without
        // it (uid is 1000 in the sandbox, so this is the effective skip).
        if unsafe { libc::getuid() } != 0 {
            eprintln!("not root; skipping CONNECT-IP e2e (needs CAP_NET_ADMIN)");
            return Ok(());
        }

        let _ = ring::default_provider().install_default();

        let Some((key, cert)) = gen_cert() else {
            eprintln!("openssl not available; skipping e2e CONNECT-IP test");
            return Ok(());
        };

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
            "--h3-bind",
            &format!("127.0.0.1:{udp_port}"),
        ]);

        let server = MasqueServer::new(cli.config)?;
        let server_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // --- Build a quinn + h3 client that trusts our self-signed cert. ---
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

        // CONNECT-IP per RFC 9484 §4: `:protocol = connect-ip`, default path.
        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://localhost:{udp_port}/.well-known/masque/ip/"))
            .body(())
            .expect("valid CONNECT-IP request");
        req.headers_mut()
            .insert("capsule-protocol", HeaderValue::from_static("?1"));
        req.headers_mut().insert(
            "proxy-authorization",
            HeaderValue::from_str(&format!("Bearer {TOKEN}")).expect("auth header"),
        );
        req.extensions_mut()
            .insert(Protocol::from_str("connect-ip").expect("patched h3 accepts connect-ip"));

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
            "CONNECT-IP must return 200, got {}",
            resp.status()
        );

        // Read the signalling capsules from the stream body (RFC 9297 TLV
        // framing on the stream) — they must NOT arrive as datagrams.
        let mut body: Vec<u8> = Vec::new();
        let mut assign: Option<Vec<capsule::AssignedAddress>> = None;
        let mut routes: Option<Vec<capsule::IpRange>> = None;
        loop {
            let mut chunk = match req_stream.recv_data().await.map_err(|e| anyhow!("recv_data: {e}"))? {
                Some(c) => c,
                None => break,
            };
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            let mut scanned = 0usize;
            while let Some((typ, val, used)) = capsule::split_capsule(&body[scanned..]) {
                scanned += used;
                match typ {
                    capsule::CAPSULE_ADDRESS_ASSIGN => {
                        assign = Some(
                            capsule::decode_address_value(val)
                                .ok_or_else(|| anyhow!("malformed ADDRESS_ASSIGN"))?,
                        );
                    }
                    capsule::CAPSULE_ROUTE_ADVERTISEMENT => {
                        routes = Some(
                            capsule::decode_route_value(val)
                                .ok_or_else(|| anyhow!("malformed ROUTE_ADVERTISEMENT"))?,
                        );
                    }
                    _ => {}
                }
            }
            if assign.is_some() && routes.is_some() {
                break;
            }
        }
        let assign = assign
            .ok_or_else(|| anyhow!("no ADDRESS_ASSIGN capsule on the request stream"))?;
        let routes = routes
            .ok_or_else(|| anyhow!("no ROUTE_ADVERTISEMENT capsule on the request stream"))?;
        assert_eq!(assign.len(), 1, "expected exactly one assigned address");
        assert!(!routes.is_empty(), "expected at least one advertised route");
        let client_v4 = match assign[0].address {
            std::net::IpAddr::V4(v4) => v4,
            other => anyhow::bail!("expected a v4 assignment from the default pool, got {other}"),
        };
        eprintln!(
            "ADDRESS_ASSIGN: {}/{}; ROUTE_ADVERTISEMENT: {} range(s)",
            client_v4, assign[0].prefix_len, routes.len()
        );

        // The proxy's tun address is the peer of the client's on the PtP link
        // (pool layout: proxy = block base+1, client = base+2).
        let mut octets = client_v4.octets();
        assert!(octets[3] >= 1, "client address must not be the block base");
        octets[3] -= 1;
        let proxy_v4 = std::net::Ipv4Addr::from(octets);

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

        // Negative control: a datagram with a non-zero Context ID (varint
        // 0x40 0x2A = 42) must be dropped silently — the tunnel stays up.
        sender
            .send_datagram(Bytes::from(vec![0x40u8, 0x2A, 0x00]))
            .map_err(|e| anyhow!("send_datagram(nonzero-cid): {e}"))?;

        // Data plane: ICMP echo request to the proxy's tun address, as
        // Context ID 0 (0x00) + RAW IP packet (no TLV, no Length). The kernel
        // answers it locally (the address is on the tun device) and the reply
        // must come back the same way.
        let ping = icmpv4_echo_request(client_v4, proxy_v4, 0x1234, 1);
        let mut dgram = Vec::with_capacity(1 + ping.len());
        dgram.push(0x00);
        dgram.extend_from_slice(&ping);
        sender
            .send_datagram(Bytes::from(dgram))
            .map_err(|e| anyhow!("send_datagram(ping): {e}"))?;

        let reply = tokio::time::timeout(Duration::from_secs(10), dgram_rx.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for ICMP echo reply"))?
            .ok_or_else(|| anyhow!("datagram channel closed"))?;
        assert_eq!(
            reply[0], 0x00,
            "reply datagram must start with Context ID 0 (0x00)"
        );
        let pkt = &reply[1..];
        assert!(pkt.len() >= 20, "echo reply must be a raw IPv4 packet");
        assert_eq!(pkt[0] >> 4, 4, "reply payload must be a RAW IPv4 packet (no capsule TLV)");
        assert_eq!(pkt[9], 1, "reply must be ICMP");
        assert_eq!(
            std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
            proxy_v4,
            "echo reply source must be the proxy tun address"
        );

        // Clean up: keep handles alive until here, then tear down.
        drop(req_stream);
        drop(send_request);
        drop(h3_conn);
        endpoint.close(0u32.into(), b"test done");
        server_handle.abort();
        Ok(())
    }

    /// Build a well-formed ICMPv4 echo request (`src -> dst`) as a raw IPv4
    /// packet with correct header/ICMP checksums. Used by the root-gated
    /// CONNECT-IP e2e.
    fn icmpv4_echo_request(
        src: std::net::Ipv4Addr,
        dst: std::net::Ipv4Addr,
        ident: u16,
        seq: u16,
    ) -> Vec<u8> {
        let payload = b"masque-connect-ip-e2e-ping";
        let mut icmp = Vec::with_capacity(8 + payload.len());
        icmp.push(8); // type: echo request
        icmp.push(0); // code
        icmp.extend_from_slice(&[0, 0]); // checksum placeholder
        icmp.extend_from_slice(&ident.to_be_bytes());
        icmp.extend_from_slice(&seq.to_be_bytes());
        icmp.extend_from_slice(payload);
        let cs = ip_checksum(&icmp);
        icmp[2..4].copy_from_slice(&cs.to_be_bytes());

        let total = 20 + icmp.len();
        let mut ip = Vec::with_capacity(total);
        ip.push(0x45); // v4, IHL 5
        ip.push(0); // DSCP/ECN
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0]); // identification
        ip.extend_from_slice(&[0, 0]); // flags/fragment offset
        ip.push(64); // TTL
        ip.push(1); // protocol: ICMP
        ip.extend_from_slice(&[0, 0]); // checksum placeholder
        ip.extend_from_slice(&src.octets());
        ip.extend_from_slice(&dst.octets());
        let cs = ip_checksum(&ip);
        ip[10..12].copy_from_slice(&cs.to_be_bytes());
        ip.extend_from_slice(&icmp);
        ip
    }

    /// RFC 1071 internet checksum.
    fn ip_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            let w = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
            sum += w as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

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
            "--h3-bind",
            &format!("127.0.0.1:{udp_port}"),
        ]);

        let server = MasqueServer::new(cli.config)?;
        let server_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Local UDP echo socket — the single target for the tunnel.
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

        // CONNECT-UDP to the echo socket, in the RFC 9298 §3.4 form:
        // `:authority` is the *proxy* (localhost:udp_port) and the target lives
        // in `:path` per the default URI template.
        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!(
                "https://localhost:{udp_port}/.well-known/masque/udp/127.0.0.1/{}/",
                echo_addr.port()
            ))
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

        // Send a UDP payload to the echo target. RFC 9298 §4.2 wire format:
        // Context ID 0 (a single 0x00 byte) + the raw UDP payload — no TLV,
        // no Length.
        let payload = b"masque-e2e-roundtrip-payload";
        let mut dgram = Vec::with_capacity(1 + payload.len());
        dgram.push(0x00);
        dgram.extend_from_slice(payload);
        sender
            .send_datagram(Bytes::from(dgram))
            .map_err(|e| anyhow!("send_datagram: {e}"))?;

        // The echo socket bounces it back; the tunnel must return Context ID 0
        // + the raw UDP payload.
        let got = tokio::time::timeout(Duration::from_secs(10), dgram_rx.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for echoed datagram"))?
            .ok_or_else(|| anyhow!("datagram channel closed"))?;
        assert_eq!(
            got[0], 0x00,
            "server datagram must start with Context ID 0 (0x00), got {:02x?}",
            &got[..got.len().min(8)]
        );
        assert_eq!(
            &got[1..],
            payload,
            "echoed UDP payload did not round-trip through the tunnel"
        );

        // Negative control: a datagram whose leading varint Context ID is
        // non-zero (0x40 0x2A = two-byte varint 42) must be dropped silently —
        // the tunnel stays up and the payload is never echoed back.
        let mut bad = vec![0x40u8, 0x2A];
        bad.extend_from_slice(b"must-be-dropped");
        sender
            .send_datagram(Bytes::from(bad))
            .map_err(|e| anyhow!("send_datagram(nonzero-cid): {e}"))?;

        // A subsequent conformant datagram still round-trips (tunnel alive).
        let payload2 = b"masque-e2e-after-nonzero-cid";
        let mut dgram2 = Vec::with_capacity(1 + payload2.len());
        dgram2.push(0x00);
        dgram2.extend_from_slice(payload2);
        sender
            .send_datagram(Bytes::from(dgram2))
            .map_err(|e| anyhow!("send_datagram(2): {e}"))?;
        let got2 = tokio::time::timeout(Duration::from_secs(10), dgram_rx.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for post-control echo (tunnel died?)"))?
            .ok_or_else(|| anyhow!("datagram channel closed"))?;
        assert_eq!(got2[0], 0x00, "post-control datagram must also use Context ID 0");
        assert_eq!(&got2[1..], payload2, "second echo mismatch");

        // ...and the dropped payload must NEVER come back.
        let extra = tokio::time::timeout(Duration::from_millis(500), dgram_rx.recv()).await;
        assert!(
            extra.is_err(),
            "datagram with non-zero Context ID must be dropped silently, got {extra:?}"
        );

        // Clean up: keep handles alive until here, then tear down.
        drop(req_stream);
        drop(send_request);
        drop(h3_conn);
        endpoint.close(0u32.into(), b"test done");
        server_handle.abort();
        Ok(())
    }

    /// End-to-end **plain TCP CONNECT** (RFC 9114 §4.4) test. Drives the actual
    /// `MasqueServer` with a real `quinn` + `h3` client over a freshly generated
    /// self-signed certificate, sends a plain `CONNECT` (NO `:protocol`) to a
    /// local TCP echo server, asserts `200`, and round-trips a payload through
    /// the h3 stream.
    ///
    /// Unlike `CONNECT-IP`, `h3` 0.0.8 *can* represent a plain `CONNECT` (its
    /// `Option<Protocol>` is `None`), so this e2e is genuinely runnable today.
    /// It is `#[ignore]`d (and a no-op if `openssl` is absent) so it does not run
    /// in the default `cargo test`; run it explicitly:
    ///
    /// ```text
    /// cargo test --lib -- --ignored e2e_tcp_connect_roundtrip
    /// ```
    ///
    /// The negative control at the end sends an extended CONNECT carrying a
    /// `:protocol` (h3 0.0.8 cannot encode `websocket` at all, so the runnable
    /// control uses `webtransport`, the only other `:protocol` h3 can encode) and
    /// asserts the response is NOT `200` — proving the dispatcher does not route a
    /// `:protocol`-bearing request to the plain TCP tunnel (so the test is not
    /// vacuous).
    #[tokio::test]
    #[ignore = "requires openssl + network; run with: cargo test --lib -- --ignored e2e_tcp_connect_roundtrip"]
    async fn e2e_tcp_connect_roundtrip() -> anyhow::Result<()> {
        let Some((key, cert)) = gen_cert() else {
            eprintln!("openssl not available; skipping e2e TCP CONNECT test");
            return Ok(());
        };

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
            "--h3-bind",
            &format!("127.0.0.1:{udp_port}"),
        ]);

        let server = MasqueServer::new(cli.config)?;
        let server_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Local TCP echo server — the single target for the tunnel.
        let echo = TcpListener::bind("127.0.0.1:0").await?;
        let echo_addr = echo.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });

        // Build a quinn + h3 client that trusts our self-signed cert (SANs:
        // DNS:localhost, IP:127.0.0.1). Connect with server_name "localhost" so
        // the real webpki verifier accepts it — no custom verifier needed.
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
        let tp = TransportConfig::default();
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
        builder.enable_extended_connect(true);
        let (h3_conn, mut send_request) = builder
            .build(h3_quinn_conn)
            .await
            .map_err(|e| anyhow!("h3 client: {e}"))?;

        // --- Plain TCP CONNECT to the echo target (NO :protocol) ---
        // `:authority` carries the target (host:port) — exactly like an HTTP/1.1
        // CONNECT. The h3 client forces `:scheme=https` and `:path=/`, neither of
        // which affects the target (read from `:authority` on the server).
        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://127.0.0.1:{}/", echo_addr.port()))
            .body(())
            .expect("valid plain TCP CONNECT request");
        req.headers_mut().insert(
            "proxy-authorization",
            HeaderValue::from_str(&format!("Bearer {TOKEN}")).expect("auth header"),
        );
        // Intentionally NO `:protocol` extension -> plain TCP CONNECT.

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
            "plain TCP CONNECT must return 200, got {}",
            resp.status()
        );

        // Send a payload to the echo target via the request body.
        let payload = b"masque-tcp-connect-e2e-roundtrip";
        req_stream
            .send_data(Bytes::copy_from_slice(payload))
            .await
            .map_err(|e| anyhow!("send_data: {e}"))?;
        // Close the request body (client finished sending).
        req_stream.finish().await.map_err(|e| anyhow!("finish: {e}"))?;

        // Read the echoed bytes back from the response body.
        let mut got = Vec::new();
        while let Some(mut buf) = req_stream
            .recv_data()
            .await
            .map_err(|e| anyhow!("recv_data: {e}"))?
        {
            got.extend_from_slice(&buf.copy_to_bytes(buf.remaining()));
        }
        assert_eq!(
            &got[..],
            payload,
            "echoed TCP payload did not round-trip through the tunnel"
        );

        // --- Negative control: an extended CONNECT carrying a `:protocol` must
        // NOT return 200. h3 0.0.8 cannot encode `websocket` at all (it is
        // rejected by h3 with H3_MESSAGE_ERROR before our code runs), so the
        // runnable control here uses `webtransport` — the only other `:protocol`
        // h3 can encode — which the server dispatches to 501. Either way the
        // dispatcher proves it does NOT treat a `:protocol`-bearing extended
        // CONNECT as a plain TCP tunnel.
        let mut bad_req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://localhost:{udp_port}/"))
            .body(())
            .expect("valid extended CONNECT request");
        bad_req.headers_mut().insert(
            "proxy-authorization",
            HeaderValue::from_str(&format!("Bearer {TOKEN}")).expect("auth header"),
        );
        bad_req.extensions_mut().insert(Protocol::WEB_TRANSPORT);

        let mut bad_stream = match send_request.send_request(bad_req).await {
            Ok(s) => s,
            // h3 itself may reject the `:protocol` before our code runs; that
            // also proves it is not served as a 200 TCP tunnel.
            Err(_) => {
                eprintln!(
                    "negative control: h3 rejected the webtransport :protocol (expected) -> not 200, OK"
                );
                drop(req_stream);
                drop(send_request);
                drop(h3_conn);
                endpoint.close(0u32.into(), b"test done");
                server_handle.abort();
                return Ok(());
            }
        };
        let bad_resp = bad_stream
            .recv_response()
            .await
            .map_err(|e| anyhow!("recv_response(neg): {e}"))?;
        assert_ne!(
            bad_resp.status(),
            StatusCode::OK,
            "a :protocol-bearing extended CONNECT must NOT be served as a plain TCP tunnel"
        );

        // Clean up.
        drop(req_stream);
        drop(send_request);
        drop(h3_conn);
        endpoint.close(0u32.into(), b"test done");
        server_handle.abort();
        Ok(())
    }

    /// End-to-end **RFC 9220 WebSocket-over-HTTP/3** test. This is the
    /// end-to-end proof that the patched `h3` accepts arbitrary extended-CONNECT
    /// `:protocol` values: a real `quinn` + `h3` client sends `CONNECT` with
    /// `:protocol = websocket` to a local TCP echo, asserts `200`, and
    /// round-trips a payload through the h3 stream (the proxy treats it as a byte
    /// pipe, exactly like a plain TCP CONNECT).
    ///
    /// Negative controls:
    ///   * a plain TCP CONNECT (no `:protocol`) also returns 200 and round-trips,
    ///     proving the websocket path is routed to the same TCP tunnel;
    ///   * an unknown `:protocol` (`webtransport`, which we do not implement)
    ///     returns a non-200 status, proving the dispatcher does not collapse
    ///     every `:protocol` into the TCP tunnel.
    ///
    /// Runs against a self-signed server (needs `openssl`, no root). `#[ignore]`d
    /// so it does not run in the default `cargo test`; run it explicitly:
    ///
    /// ```text
    /// cargo test --lib -- --ignored e2e_websocket_connect_roundtrip
    /// ```
    #[tokio::test]
    #[ignore = "requires openssl + network; run with: cargo test --lib -- --ignored e2e_websocket_connect_roundtrip"]
    async fn e2e_websocket_connect_roundtrip() -> anyhow::Result<()> {
        let Some((key, cert)) = gen_cert() else {
            eprintln!("openssl not available; skipping e2e WebSocket-over-H3 test");
            return Ok(());
        };

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
            "--h3-bind",
            &format!("127.0.0.1:{udp_port}"),
        ]);

        let server = MasqueServer::new(cli.config)?;
        let server_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Local TCP echo server — the origin the WebSocket-over-H3 tunnel pipes to.
        let echo = TcpListener::bind("127.0.0.1:0").await?;
        let echo_addr = echo.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });

        // Build a quinn + h3 client that trusts our self-signed cert (SANs:
        // DNS:localhost, IP:127.0.0.1). Connect with server_name "localhost".
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
        let tp = TransportConfig::default();
        client_cfg.transport_config(Arc::new(tp));

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_cfg);

        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), udp_port);
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
        // RFC 9220 bootstrapping is an extended CONNECT, so the client must
        // negotiate extended-CONNECT.
        builder.enable_extended_connect(true);
        let (h3_conn, mut send_request) = builder
            .build(h3_quinn_conn)
            .await
            .map_err(|e| anyhow!("h3 client: {e}"))?;

        // --- RFC 9220 WebSocket-over-H3 CONNECT: `:protocol = websocket`,
        // target in `:authority` (host:port), like a plain TCP CONNECT. ---
        let mut ws_req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://127.0.0.1:{}/", echo_addr.port()))
            .body(())
            .expect("valid WebSocket extended CONNECT request");
        ws_req.headers_mut().insert(
            "proxy-authorization",
            HeaderValue::from_str(&format!("Bearer {TOKEN}")).expect("auth header"),
        );
        // With the patched h3 this is `Protocol::Other("websocket")` rather than
        // `Err(InvalidProtocol)` — and the dispatcher routes it to the TCP tunnel.
        ws_req
            .extensions_mut()
            .insert(Protocol::from_str("websocket").expect("patched h3 accepts websocket"));

        let mut ws_stream = send_request
            .send_request(ws_req)
            .await
            .map_err(|e| anyhow!("send_request(websocket): {e}"))?;
        let ws_resp = ws_stream
            .recv_response()
            .await
            .map_err(|e| anyhow!("recv_response(websocket): {e}"))?;
        assert_eq!(
            ws_resp.status(),
            StatusCode::OK,
            "RFC 9220 WebSocket CONNECT must return 200, got {}",
            ws_resp.status()
        );

        // Round-trip a payload through the WebSocket tunnel body.
        let ws_payload = b"rfc9220-websocket-over-h3-roundtrip";
        ws_stream
            .send_data(Bytes::copy_from_slice(ws_payload))
            .await
            .map_err(|e| anyhow!("send_data(websocket): {e}"))?;
        ws_stream.finish().await.map_err(|e| anyhow!("finish(websocket): {e}"))?;

        let mut ws_got = Vec::new();
        while let Some(mut buf) = ws_stream
            .recv_data()
            .await
            .map_err(|e| anyhow!("recv_data(websocket): {e}"))?
        {
            ws_got.extend_from_slice(&buf.copy_to_bytes(buf.remaining()));
        }
        assert_eq!(
            &ws_got[..],
            ws_payload,
            "echoed WebSocket payload did not round-trip through the tunnel"
        );

        // --- Positive control: a plain TCP CONNECT (no `:protocol`) must ALSO
        // return 200 and round-trip on the same connection, proving the websocket
        // path is just the TCP tunnel (the proxy does not interpret WebSocket). ---
        let mut plain_req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://127.0.0.1:{}/", echo_addr.port()))
            .body(())
            .expect("valid plain TCP CONNECT request");
        plain_req.headers_mut().insert(
            "proxy-authorization",
            HeaderValue::from_str(&format!("Bearer {TOKEN}")).expect("auth header"),
        );
        let mut plain_stream = send_request
            .send_request(plain_req)
            .await
            .map_err(|e| anyhow!("send_request(plain): {e}"))?;
        let plain_resp = plain_stream
            .recv_response()
            .await
            .map_err(|e| anyhow!("recv_response(plain): {e}"))?;
        assert_eq!(
            plain_resp.status(),
            StatusCode::OK,
            "plain TCP CONNECT must return 200, got {}",
            plain_resp.status()
        );
        let plain_payload = b"plain-tcp-connect-control-roundtrip";
        plain_stream
            .send_data(Bytes::copy_from_slice(plain_payload))
            .await
            .map_err(|e| anyhow!("send_data(plain): {e}"))?;
        plain_stream.finish().await.map_err(|e| anyhow!("finish(plain): {e}"))?;
        let mut plain_got = Vec::new();
        while let Some(mut buf) = plain_stream
            .recv_data()
            .await
            .map_err(|e| anyhow!("recv_data(plain): {e}"))?
        {
            plain_got.extend_from_slice(&buf.copy_to_bytes(buf.remaining()));
        }
        assert_eq!(&plain_got[..], plain_payload, "plain TCP control round-trip failed");

        // --- Negative control: an unknown `:protocol` (`webtransport`, which we
        // do not implement) must NOT return 200. ---
        let mut bad_req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://localhost:{udp_port}/"))
            .body(())
            .expect("valid extended CONNECT request");
        bad_req.headers_mut().insert(
            "proxy-authorization",
            HeaderValue::from_str(&format!("Bearer {TOKEN}")).expect("auth header"),
        );
        bad_req.extensions_mut().insert(Protocol::WEB_TRANSPORT);

        let mut bad_stream = send_request
            .send_request(bad_req)
            .await
            .map_err(|e| anyhow!("send_request(neg): {e}"))?;
        let bad_resp = bad_stream
            .recv_response()
            .await
            .map_err(|e| anyhow!("recv_response(neg): {e}"))?;
        assert_ne!(
            bad_resp.status(),
            StatusCode::OK,
            "an unimplemented :protocol (webtransport) must NOT be served as a 200 tunnel"
        );

        // Clean up.
        drop(send_request);
        drop(h3_conn);
        endpoint.close(0u32.into(), b"test done");
        server_handle.abort();
        Ok(())
    }
}
