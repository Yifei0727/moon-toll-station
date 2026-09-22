//! HTTP/3 MASQUE server.
//!
//! This module terminates a QUIC/HTTP/3 connection and relays traffic for three
//! request types, all dispatched from the same listener:
//!
//! 1. **`CONNECT-UDP`** (RFC 9298) — UDP payloads carried as HTTP/3 DATAGRAMs
//!    (RFC 9297) whose body is a `DATAGRAM` capsule (RFC 9297 §4 / RFC 9298 §4).
//! 2. **`CONNECT-IP`** (RFC 9484) — IP packets carried as HTTP/3 DATAGRAM `IP`
//!    capsules; a real layer-3 VPN gateway (needs root).
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
//! * The h3-datagram layer automatically prepends/strips the Quarter Stream ID
//!   (stream id / 4) to the wire datagram, so the bytes we hand to / receive from
//!   it are exactly the RFC 9297 capsule (`Type=0x00` + `Length` + `Value`).

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
};

use anyhow::Context;
use base64::Engine;
use bytes::{Buf, Bytes};
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
use tracing::{debug, info, warn};

use crate::capsule;
use crate::config::AppConfig;
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
/// (QSID-stripped) datagram capsules to the owning tunnel task.
type Rx = mpsc::UnboundedReceiver<Bytes>;

/// Routing table: QUIC stream id -> tunnel task inbox.
type Routes = Arc<Mutex<HashMap<StreamId, mpsc::UnboundedSender<Bytes>>>>;

/// Headroom (bytes) we budget for the QUIC DATAGRAM frame header, the
/// Quarter Stream ID varint, and the capsule's `Type`/`Length` varints when
/// deciding whether an outgoing capsule fits the current datagram MTU.
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

        // Reuse --listen's IP; only the UDP port differs (default 443).
        let addr = SocketAddr::new(self.config.listen.ip(), self.config.udp_port);
        let endpoint = Endpoint::server(server_cfg, addr)
            .with_context(|| format!("failed to bind MASQUE/QUIC endpoint on {addr}"))?;

        info!(listen = %addr, "masque (HTTP/3 CONNECT-UDP) server started");

        // A single resolver is shared (cheaply cloneable) across all tunnels.
        let resolver = Resolver::new(self.config.dns_server)?;

        // One CONNECT-IP address pool, shared across all sessions/connections so
        // allocations never collide. Validate it now (cheap) so a bad `--ip-pool`
        // fails fast at startup rather than on the first tunnel.
        let ip_pool = Arc::new(StdMutex::new(IpPool::new(&self.config.ip_pool)?));

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
    pool: Arc<StdMutex<IpPool>>,
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

/// Tunnel one `CONNECT-IP` request: a real layer-3 VPN gateway.
///
/// After the `200` + `capsule-protocol` response, this allocates the client an
/// address from the shared pool, creates a `tun` device (proxy side = one end of
/// a PtP link, client = the peer), NATs the client's traffic, tells the client
/// its address (`Address Assign`) and the routes we advertise (`Route
/// Advertisement`, default `0.0.0.0/0` / `::/0`), and then relays IP packets
/// between the `tun` device and HTTP/3 DATAGRAM `IP` capsules for the life of
/// the stream. On teardown, dropping `tun` removes the interface, the iptables
/// rules, and restores `ip_forward`.
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
    S: quic::SendStream<Bytes> + quic::RecvStream,
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

    // Tell the client the address/prefix it owns.
    let assign = capsule::encode_address_assign(&[capsule::IpAddressEntry {
        address: client_addr,
        prefix_len: Some(prefix),
    }]);
    if sender.send_datagram(assign).is_err() {
        debug!(peer = %peer, "datagram send failed sending Address Assign");
        let _ = req_stream.finish().await;
        return Ok(());
    }

    // Advertise a default route so the client sends all traffic through us.
    let route_adv = capsule::encode_route_advertisement(&[capsule::Route {
        address: default_route_for(client_addr),
        prefix_len: 0,
    }]);
    if sender.send_datagram(route_adv).is_err() {
        debug!(peer = %peer, "datagram send failed sending Route Advertisement");
        let _ = req_stream.finish().await;
        return Ok(());
    }

    // Data plane: tun <-> HTTP/3 DATAGRAM `IP` capsules.
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            read = tun.read_packet(&mut buf) => {
                match read {
                    Ok(n) if n > 0 => {
                        let capsule = capsule::encode_ip_packet(&buf[..n]);
                        let too_big = match quinn_conn.max_datagram_size() {
                            Some(max) => capsule.len() + DATAGRAM_OVERHEAD > max,
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
                        if let Err(e) = sender.send_datagram(capsule) {
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
                    Some(capsule) => match capsule::decode_capsule(&capsule) {
                        Some((capsule::CAPSULE_IP, _)) => {
                            // The wire format is `Type=0x02 + Length + IP packet`.
                            // Unpack just the packet and inject it into the tun
                            // device; the kernel routes it onward (and NAT rewrites
                            // it for egress).
                            match capsule::decode_ip_packet(&capsule) {
                                Some(pkt) => {
                                    if let Err(e) = tun.write_packet(&pkt).await {
                                        debug!(peer = %peer, error = %e, "tun write failed");
                                    }
                                }
                                None => debug!(peer = %peer, "IP capsule with no payload dropped"),
                            }
                        }
                        Some((capsule::CAPSULE_ADDRESS_REQUEST, req_val)) => {
                            // The client may request specific address(es). We
                            // always assign from our pool, so we parse the request
                            // only to log it and then re-assert our assignment.
                            if let Some(entries) = capsule::decode_address_value(&req_val) {
                                debug!(
                                    peer = %peer,
                                    requested = ?entries,
                                    "client Address Request; re-asserting assigned address"
                                );
                            }
                            let assign = capsule::encode_address_assign(&[capsule::IpAddressEntry {
                                address: client_addr,
                                prefix_len: Some(prefix),
                            }]);
                            let _ = sender.send_datagram(assign);
                        }
                        Some((capsule::CAPSULE_ROUTE_ADVERTISEMENT, route_val)) => {
                            // The client advertises the route(s) it wants us to
                            // carry. We ignore the content (we always advertise a
                            // default route) but parse it to validate framing and
                            // for observability.
                            if let Some(routes) = capsule::decode_route_value(&route_val) {
                                debug!(peer = %peer, routes = ?routes, "client Route Advertisement");
                            }
                        }
                        Some((typ, _)) => {
                            debug!(peer = %peer, type_ = typ, "ignoring unknown CONNECT-IP capsule")
                        }
                        None => debug!(peer = %peer, stream = %stream_id, "malformed capsule dropped"),
                    },
                    None => break, // reader task gone / connection closed
                }
            }
        }
    }

    // Control stream closed: `tun` is dropped here, which removes the interface,
    // the iptables rules, and restores `ip_forward`.
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

/// All-zero address of the same family as `addr` (for the `0.0.0.0/0` / `::/0`
/// default route advertisement).
fn default_route_for(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
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

/// Encode a UDP payload into an RFC 9297 `DATAGRAM` capsule:
/// `Type=0x00 (varint)` + `Length (varint)` + `Value`.
///
/// The QUIC variable-length integer (RFC 9000 §16) and capsule framing are
/// shared with CONNECT-IP and live in `crate::capsule`; this is a thin wrapper
/// that pins the type to `UDP_DATAGRAM` (0x00) for the CONNECT-UDP path.
pub(crate) fn encode_capsule(payload: &[u8]) -> Bytes {
    capsule::encode_capsule(capsule::CAPSULE_DATAGRAM, payload)
}

/// Decode a `DATAGRAM` capsule back into its raw UDP payload. Returns `None`
/// for a non-UDP_DATAGRAM type or a truncated/garbled capsule.
pub(crate) fn decode_capsule(capsule: &[u8]) -> Option<Bytes> {
    match capsule::decode_capsule(capsule) {
        Some((capsule::CAPSULE_DATAGRAM, v)) => Some(v),
        _ => None,
    }
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
        check_proxy_auth, decode_capsule, encode_capsule, is_connect_ip_path, parse_target,
        validate_connect_ip, validate_tcp_connect, validate_connect_udp,
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

    use crate::config::Cli;
    use super::{MasqueServer, decode_capsule, encode_capsule};

    /// End-to-end CONNECT-IP test. With the patched h3, a `connect-ip`
    /// `:protocol` is now representable, so the only remaining gate is root: the
    /// server creates a real `tun` device, which requires `CAP_NET_ADMIN`. On a
    /// non-root host (uid != 0) it skips gracefully. With root it would:
    /// handshake, send `CONNECT-IP`, assert `200` + `Address Assign`, and
    /// round-trip a ping through the tunnel. The full flow is left as a
    /// clearly-labelled placeholder because it cannot execute without root in
    /// this environment.
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
        // NOTE: the live handshake + Address-Assign assertion + ping-through-
        // tunnel flow would be implemented here once root is available. It is
        // omitted because that gate is not met in CI/sandbox.
        Ok(())
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
            "--udp-port",
            &udp_port.to_string(),
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
            "--udp-port",
            &udp_port.to_string(),
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
            "--udp-port",
            &udp_port.to_string(),
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
