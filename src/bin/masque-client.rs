//! `masque-client` — a standalone end-to-end verification client for the
//! MASQUE/HTTP/3 listener served by `auto-server --enable h3`.
//!
//! It speaks all four modes the server dispatches from one listener:
//!
//! | subcommand | protocol | wire shape |
//! |------------|----------|------------|
//! | `udp`      | CONNECT-UDP (RFC 9298) | `:protocol=connect-udp`, target in `:path`, payload = `Context ID 0` + UDP payload |
//! | `tcp`      | plain TCP CONNECT (RFC 9114 §4.4) | no `:protocol`, target in `:authority`, byte pipe |
//! | `ws`       | WebSocket over HTTP/3 (RFC 9220) | `:protocol=websocket`, target in `:authority`, byte pipe |
//! | `ip`       | CONNECT-IP (RFC 9484) | `:protocol=connect-ip`, signalling capsules on the stream, packets = `Context ID 0` + raw IP |
//!
//! Every mode reports `PASS`/`FAIL` per step (handshake, response status, data
//! round-trip) and exits non-zero if anything fails, so it can be dropped into
//! a shell loop or CI step:
//!
//! ```text
//! masque-client --proxy 127.0.0.1:4433 --ca cert.pem --token "$TOKEN" udp --target 127.0.0.1:4000
//! ```
//!
//! Two important honesty notes:
//!
//! * **Certificate trust.** The client trusts the operating system's
//!   certificate store by default. `--ca` (repeatable) adds extra anchors on
//!   top of that, which is how self-signed test certificates are trusted.
//!   There is deliberately no `--insecure`: verification always runs against a
//!   real webpki root store — no custom verifier, no disabled checks. Adding
//!   certificate pinning bypass would require enabling rustls'
//!   `dangerous_configuration` feature purely for this tool.
//! * **Not independent interop.** This client reuses the server's own
//!   `capsule` codec, so a green run proves round-trip behaviour, not
//!   third-party conformance. `masque-go` remains the independent test.

use std::{
    future::Future,
    io::Write as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use bytes::{Buf, Bytes, BytesMut};
use clap::{Args, Parser, Subcommand};
use h3::ext::Protocol;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_quinn::Connection as H3QuinnConnection;
use http::{HeaderValue, Method, Request, StatusCode};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use quinn::{ClientConfig, Endpoint, TransportConfig};
use rustls::RootCertStore;
use tokio::sync::mpsc;

use auto_server::capsule;

// ---------------------------------------------------------------------------
// Convenience aliases for the concrete HTTP/3-over-QUIC stack we drive.
// ---------------------------------------------------------------------------

/// [`h3::quic::OpenStreams`] implementation of the h3-quinn transport.
type H3Streams = <H3QuinnConnection as h3::quic::Connection<Bytes>>::OpenStreams;

/// A connected HTTP/3 client (needed for its datagram handles).
type H3Client = h3::client::Connection<H3QuinnConnection, Bytes>;

/// The request-opening half of that client.
type H3SendRequest = h3::client::SendRequest<H3Streams, Bytes>;

/// RFC 9484 §4 default `connect-ip` URI template (no path variables).
const MASQUE_IP_PATH: &str = "/.well-known/masque/ip/";

/// RFC 9298 §2 default `connect-udp` URI template prefix. The two remaining
/// segments are `{target_host}/{target_port}/`.
const MASQUE_UDP_PATH: &str = "/.well-known/masque/udp/";

/// Characters percent-encoded in the `{target_host}` path segment. RFC 9298
/// §3.1 requires colons to be encoded, and delimiters must never leak into the
/// segment or the server cannot split it back into host/port.
const HOST_ENCODE: &AsciiSet = &CONTROLS
    .add(b':')
    .add(b'/')
    .add(b'?')
    .add(b'#')
    .add(b'[')
    .add(b']');

/// How long to wait for the proxy's listener to accept us before giving up on
/// the handshake when no `--timeout-ms` budget covers it.
const HANDSHAKE_RETRY_BUDGET: Duration = Duration::from_secs(10);

/// How long to wait for one datagram/packet echo before declaring the
/// round-trip step a failure.
const ROUNDTRIP_WAIT: Duration = Duration::from_secs(10);

/// How long to wait for a body chunk while reading CONNECT-IP signalling
/// capsules (the control stream stays open for the tunnel's lifetime, so this
/// must not wait for EOF).
const CAPSULE_WAIT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "masque-client",
    about = "End-to-end client for the auto-server MASQUE/HTTP/3 proxy (CONNECT-UDP, CONNECT-IP, TCP CONNECT, WebSocket)",
    long_about = None
)]
struct Cli {
    #[command(flatten)]
    common: Common,

    #[command(subcommand)]
    mode: Mode,
}

/// Options shared by every mode.
#[derive(Debug, Clone, Args)]
struct Common {
    /// MASQUE proxy to connect to, `host:port` (the server's --h3-bind).
    #[arg(long, value_name = "HOST:PORT")]
    proxy: String,

    /// Proxy authorization token, sent as `Proxy-Authorization: Bearer <TOKEN>`.
    /// Required by the server whenever it was started with --auth-token.
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,

    /// PEM file whose certificates are added as *extra* trust anchors on top
    /// of the OS certificate store (the default root of trust). Repeatable.
    /// Needed for self-signed / private-CA deployments. There is no --insecure.
    #[arg(long = "ca", value_name = "PEM")]
    ca: Vec<PathBuf>,

    /// TLS server name used for certificate verification and QUIC SNI.
    /// Defaults to the host part of --proxy. Must match a SAN in the server
    /// certificate (the throwaway certs used in testing use `localhost`).
    #[arg(long, value_name = "NAME")]
    server_name: Option<String>,

    /// Cap QUIC datagram size when the path has a smaller MTU (avoids
    /// blackholed/fragmented handshakes). Applied to this client's transport
    /// config (advertised max payload, initial MTU and MTU-discovery upper
    /// bound). Must be >= 1200 (the QUIC minimum). Use the same value the
    /// server was started with.
    #[arg(long, value_name = "BYTES")]
    max_mtu: Option<u16>,

    /// Overall budget for the whole run, in milliseconds.
    #[arg(long, value_name = "MS", default_value_t = 15_000)]
    timeout_ms: u64,
}

#[derive(Debug, Subcommand)]
enum Mode {
    /// CONNECT-UDP (RFC 9298): tunnel UDP datagrams through HTTP/3 DATAGRAMs.
    Udp(UdpArgs),
    /// Plain TCP CONNECT (RFC 9114 §4.4): a byte pipe over an HTTP/3 stream.
    Tcp(TunnelArgs),
    /// WebSocket over HTTP/3 (RFC 9220): `:protocol=websocket` byte pipe.
    Ws(TunnelArgs),
    /// CONNECT-IP (RFC 9484): layer-3 tunnel; needs root on the *server*.
    Ip(IpArgs),
}

#[derive(Debug, Args)]
struct UdpArgs {
    /// UDP target to reach through the tunnel, `host:port`.
    #[arg(long, value_name = "HOST:PORT")]
    target: String,

    /// Name to look up in the default DNS A query sent through the tunnel.
    #[arg(long, value_name = "NAME", default_value = "example.com")]
    dns: String,

    /// Send these raw bytes (hex) as the UDP payload instead of a DNS query.
    #[arg(long, value_name = "HEX", conflicts_with = "dns")]
    payload_hex: Option<String>,
}

#[derive(Debug, Args)]
struct TunnelArgs {
    /// Target to CONNECT to, `host:port`. Carried in the request's
    /// `:authority`, like an HTTP/1.1 CONNECT.
    #[arg(long, value_name = "HOST:PORT")]
    target: String,

    /// Raw bytes to send through the tunnel once the `2xx` arrives.
    #[arg(long, value_name = "STR", conflicts_with = "http_get")]
    payload: Option<String>,

    /// Send a minimal HTTP/1.1 GET through the tunnel instead of --payload.
    #[arg(long, value_name = "PATH")]
    http_get: Option<String>,
}

#[derive(Debug, Args)]
struct IpArgs {
    /// IPv4 destination for the ICMP echo request sent through the tunnel.
    /// Defaults to the proxy's end of the point-to-point link: with the server's
    /// default pool layout the client is `<block base>+2` and the proxy
    /// `<block base>+1`, i.e. the address just below the assigned one.
    #[arg(long, value_name = "IP")]
    ping: Option<Ipv4Addr>,
}

// ---------------------------------------------------------------------------
// Step reporting
// ---------------------------------------------------------------------------

/// Run `fut` as one labelled verification step, printing `PASS`/`FAIL` and the
/// reason inline so the transcript shows exactly which step broke.
///
/// Evidence lines emitted with [`detail`] inside the future are held back until
/// the verdict is printed, so each step reads as
/// `  <label> ... PASS` followed by its own detail lines.
async fn check<T>(label: &str, fut: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    print!("  {label:<36} ... ");
    let _ = std::io::stdout().flush();
    let result = fut.await;
    match &result {
        Ok(_) => println!("PASS"),
        Err(e) => {
            println!("FAIL");
            print_reason(e);
        }
    }
    flush_details();
    result
}

fn print_reason(e: &anyhow::Error) {
    println!("      reason: {e:#}");
    for cause in e.chain().skip(1) {
        if cause.to_string() != e.to_string() {
            println!("      caused by: {cause}");
        }
    }
}

/// Evidence for the step that is currently running, printed after its verdict.
static STEP_DETAILS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Queue one indented line of evidence for the step being run. Never held across
/// an await, so the lock cannot block the runtime.
fn detail(line: &str) {
    if let Ok(mut guard) = STEP_DETAILS.lock() {
        guard.push(line.to_string());
    }
}

/// Indented line printed immediately (run headers, outside any step).
fn info(line: &str) {
    println!("      {line}");
}

fn flush_details() {
    if let Ok(mut guard) = STEP_DETAILS.lock() {
        for line in guard.drain(..) {
            println!("      {line}");
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> ExitCode {
    // Exactly one rustls crypto provider per process — `ring`, the same one the
    // server installs (see src/main.rs). Without it the QUIC handshake fails
    // with "no process-level CryptoProvider available".
    let _ = rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let cli = Cli::parse();
    if let Some(mtu) = cli.common.max_mtu
        && mtu < 1200
    {
        eprintln!(
            "RESULT: FAIL\n      reason: --max-mtu {mtu} is below the QUIC minimum of 1200 bytes"
        );
        return ExitCode::FAILURE;
    }
    let budget = Duration::from_millis(cli.common.timeout_ms);

    match tokio::time::timeout(budget, dispatch(cli)).await {
        Ok(Ok(())) => {
            println!("RESULT: PASS");
            ExitCode::SUCCESS
        }
        Ok(Err(e)) => {
            println!("RESULT: FAIL");
            println!("      reason: {e:#}");
            ExitCode::FAILURE
        }
        Err(_) => {
            println!("RESULT: FAIL");
            println!("      reason: timed out after {} ms", budget.as_millis());
            ExitCode::FAILURE
        }
    }
}

async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.mode {
        Mode::Udp(args) => run_udp(&cli.common, args).await,
        Mode::Tcp(args) => run_tunnel(&cli.common, args, None).await,
        Mode::Ws(args) => {
            run_tunnel(
                &cli.common,
                args,
                Some(Protocol::from_str("websocket").expect("patched h3 accepts websocket")),
            )
            .await
        }
        Mode::Ip(args) => run_ip(&cli.common, args).await,
    }
}

// ---------------------------------------------------------------------------
// Connection setup
// ---------------------------------------------------------------------------

/// A live QUIC endpoint + HTTP/3 client connection plus the request opener.
struct Proxy {
    endpoint: Endpoint,
    h3: H3Client,
    send_request: H3SendRequest,
}

impl Proxy {
    /// Open a QUIC connection to `server` (verified as `name`) and complete the
    /// HTTP/3 handshake with the two SETTINGS every MASQUE mode needs:
    /// DATAGRAM (RFC 9297) and extended CONNECT (RFC 8441 §4).
    async fn connect(
        server: SocketAddr,
        name: &str,
        roots: RootCertStore,
        max_mtu: Option<u16>,
    ) -> anyhow::Result<Self> {
        let mut client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
            .context("failed to build QUIC client crypto config")?;

        let mut client_cfg = ClientConfig::new(Arc::new(crypto));
        let mut tp = TransportConfig::default();
        // Both must be set: `None` would disable *inbound* datagrams, without
        // which CONNECT-UDP / CONNECT-IP have no downlink.
        tp.datagram_receive_buffer_size(Some(64 * 1024));
        tp.datagram_send_buffer_size(64 * 1024);
        // Built via `Endpoint::new` (rather than `Endpoint::client`) so a
        // `--max-mtu` cap can be applied to the `EndpointConfig` as well.
        let mut endpoint_cfg = quinn::EndpointConfig::default();
        if let Some(mtu) = max_mtu {
            auto_server::masque::apply_max_mtu(&mut tp, &mut endpoint_cfg, mtu)?;
        }
        client_cfg.transport_config(Arc::new(tp));

        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .expect("static bind address parses");
        let socket = std::net::UdpSocket::bind(bind)
            .with_context(|| format!("failed to bind QUIC client on {bind}"))?;
        let mut endpoint = Endpoint::new(endpoint_cfg, None, socket, Arc::new(quinn::TokioRuntime))
            .with_context(|| format!("failed to start QUIC client on {bind}"))?;
        endpoint.set_default_client_config(client_cfg);

        // Retry briefly so a script that starts the server and the client
        // together does not race the listener.
        let deadline = tokio::time::Instant::now() + HANDSHAKE_RETRY_BUDGET;
        let quinn_conn = loop {
            let attempt = endpoint.connect(server, name);
            match attempt {
                Ok(connecting) => match connecting.await {
                    Ok(conn) => break conn,
                    Err(e) => {
                        if tokio::time::Instant::now() >= deadline {
                            return Err(anyhow!(e)).context(format!("QUIC handshake with {server} failed"));
                        }
                    }
                },
                Err(e) => {
                    return Err(anyhow!(e)).context(format!("cannot connect to {server}"));
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };

        let mut builder = h3::client::builder();
        builder.enable_datagram(true);
        builder.enable_extended_connect(true);
        let (h3, send_request) = builder
            .build(H3QuinnConnection::new(quinn_conn))
            .await
            .context("HTTP/3 client setup failed")?;

        Ok(Self {
            endpoint,
            h3,
            send_request,
        })
    }

    /// Close the endpoint so the process can exit without waiting on drift.
    fn close(&mut self, reason: &str) {
        self.endpoint.close(0u32.into(), reason.as_bytes());
    }
}

/// Build the verification root store. The operating system's certificate store
/// is the default trust root; every `--ca` PEM is added on top as an extra
/// anchor (for self-signed / private-CA deployments). Only if the combined
/// store ends up empty do we bail: there is no certificate-verification bypass.
fn load_roots(cas: &[PathBuf]) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();

    // System anchors first (honours SSL_CERT_FILE / SSL_CERT_DIR). Certificates
    // that fail to parse as anchors are skipped: one odd entry in the OS store
    // must not break the client, and store-load errors are reported, not fatal.
    let system = rustls_native_certs::load_native_certs();
    for error in &system.errors {
        info(&format!("system certificate store: {error}"));
    }
    let mut system_count = 0usize;
    for cert in system.certs {
        if roots.add(cert).is_ok() {
            system_count += 1;
        }
    }
    info(&format!("loaded {system_count} system trust anchor(s)"));

    // --ca PEMs are additive extra anchors. Files the user named explicitly
    // stay hard errors if they cannot be read, parsed or added.
    let mut ca_count = 0usize;
    for path in cas {
        let mut reader = std::io::BufReader::new(
            std::fs::File::open(path)
                .with_context(|| format!("failed to open CA file {}", path.display()))?,
        );
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<_, _>>()
            .with_context(|| format!("failed to parse PEM in {}", path.display()))?;
        if certs.is_empty() {
            bail!("no certificate found in {}", path.display());
        }
        for cert in certs {
            roots
                .add(cert)
                .with_context(|| format!("failed to add {} as a trust anchor", path.display()))?;
            ca_count += 1;
        }
    }
    info(&format!("loaded {ca_count} trust anchor(s) from --ca"));

    if roots.is_empty() {
        bail!(
            "no trust anchors: the OS certificate store was empty and no --ca was given.\n      \
             This client has no --insecure flag on purpose; see docs/masque-client.md."
        );
    }
    Ok(roots)
}

/// Resolve `--proxy` into (socket address, TLS server name).
async fn resolve_proxy(common: &Common) -> anyhow::Result<(SocketAddr, String)> {
    let (host, port) = split_host_port(&common.proxy)?;
    let addr = tokio::net::lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("failed to resolve proxy host '{host}'"))?
        .next()
        .with_context(|| format!("proxy host '{host}' resolved to no address"))?;
    let name = common.server_name.clone().unwrap_or(host);
    Ok((addr, name))
}

/// `authority` in `host:port` form, bracketing IPv6 literals for URI use.
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Split `host:port`, tolerating a bracketed IPv6 literal.
fn split_host_port(s: &str) -> anyhow::Result<(String, u16)> {
    let host_part: String;
    let port_str: &str;
    match s.rsplit_once(':') {
        Some((h, p)) => {
            host_part = h
                .strip_prefix('[')
                .and_then(|inner| inner.strip_suffix(']'))
                .unwrap_or(h)
                .to_string();
            port_str = p;
        }
        None => bail!("expected host:port, got '{s}'"),
    }
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid port in '{s}'"))?;
    Ok((host_part, port))
}

/// Start the request every mode shares: method CONNECT, authorization, and the
/// optional extended-CONNECT `:protocol`.
fn request_for(uri: String, common: &Common) -> anyhow::Result<Request<()>> {
    let mut req = Request::builder()
        .method(Method::CONNECT)
        .uri(uri.parse::<http::Uri>().with_context(|| format!("invalid request URI '{uri}'"))?)
        .body(())
        .context("invalid CONNECT request")?;
    if let Some(token) = &common.token {
        let value = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid --token value for the Proxy-Authorization header")?;
        req.headers_mut().insert("proxy-authorization", value);
    }
    Ok(req)
}

// ---------------------------------------------------------------------------
// Mode: CONNECT-UDP (RFC 9298)
// ---------------------------------------------------------------------------

async fn run_udp(common: &Common, args: UdpArgs) -> anyhow::Result<()> {
    let (target_host, target_port) = split_host_port(&args.target)?;
    let payload = match &args.payload_hex {
        Some(hex) => parse_hex(hex).context("invalid --payload-hex")?,
        None => dns_query(&args.dns),
    };

    println!("=== mode: udp (CONNECT-UDP, RFC 9298) ===");
    info(&format!("proxy            {}", common.proxy));
    info(&format!("tunnel target    {target_host}:{target_port}"));
    println!();

    let roots = load_roots(&common.ca)?;
    let mut proxy = check("handshake (QUIC + HTTP/3)", async {
        let (addr, name) = resolve_proxy(common).await?;
        detail(&format!("connected to {addr}, server name '{name}'"));
        Proxy::connect(addr, &name, roots, common.max_mtu).await
    })
    .await?;

    let result = udp_session(&mut proxy, common, &target_host, target_port, &payload).await;
    proxy.close("masque-client done");
    result
}

/// Handshake done: send the CONNECT-UDP request and round-trip one payload.
async fn udp_session(
    proxy: &mut Proxy,
    common: &Common,
    target_host: &str,
    target_port: u16,
    payload: &[u8],
) -> anyhow::Result<()> {
    // RFC 9298 §3.4: `:authority` is the *proxy*; the target lives in `:path`.
    // Colons in an IPv6 target must be percent-encoded (§3.1).
    let encoded_host = utf8_percent_encode(target_host, HOST_ENCODE).to_string();
    let proxy_authority = authority(&server_name_or_host(common), proxy_port(common)?);
    let uri = format!("https://{proxy_authority}{MASQUE_UDP_PATH}{encoded_host}/{target_port}/");
    detail(&format!("request :path  {MASQUE_UDP_PATH}{encoded_host}/{target_port}/"));

    let mut req = request_for(uri, common)?;
    req.headers_mut()
        .insert("capsule-protocol", HeaderValue::from_static("?1"));
    req.extensions_mut().insert(Protocol::CONNECT_UDP);

    let req_stream = check("CONNECT-UDP accepted", async {
        let mut stream = proxy
            .send_request
            .send_request(req)
            .await
            .context("send_request failed")?;
        let resp = stream.recv_response().await.context("recv_response failed")?;
        if resp.status() != StatusCode::OK {
            bail!(
                "expected 200, got {} (auth missing? try --token; wrong path?)",
                resp.status()
            );
        }
        detail("status 200, capsule-protocol: ?1");
        Ok(stream)
    })
    .await?;

    // Downlink: one task drains every inbound datagram onto a channel, keeping
    // only the ones for this stream (h3-datagram already stripped the Quarter
    // Stream ID).
    let stream_id = req_stream.id();
    let mut reader = proxy.h3.get_datagram_reader();
    let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();    tokio::spawn(async move {
        while let Ok(d) = reader.read_datagram().await {
            if d.stream_id() == stream_id && tx.send(d.into_payload()).is_err() {
                break;
            }
        }
    });

    let mut sender = proxy.h3.get_datagram_sender(stream_id);
    check("datagram round-trip", async {
        // RFC 9298 §4.2: Context ID 0 (one 0x00 byte) + the raw UDP payload.
        let mut dgram = BytesMut::with_capacity(1 + payload.len());
        capsule::put_varint(&mut dgram, 0);
        dgram.extend_from_slice(payload);
        sender
            .send_datagram(dgram.freeze())
            .map_err(|e| anyhow!("send_datagram failed: {e}"))?;

        let reply = tokio::time::timeout(ROUNDTRIP_WAIT, rx.recv())
            .await
            .map_err(|_| anyhow!("no reply within {:?}", ROUNDTRIP_WAIT))?
            .ok_or_else(|| anyhow!("datagram channel closed"))?;
        let payload_back = capsule::strip_context_id(&reply)
            .ok_or_else(|| anyhow!("reply does not start with Context ID 0: {:02x?}", &reply[..reply.len().min(8)]))?;

        detail(&format!("reply: {} bytes", payload_back.len()));
        if payload_back == payload {
            detail("reply is an exact echo of the request payload");
        } else {
            detail("reply is NOT an echo of the request (target is not an echo server)");
            detail(&format!("sent     ({:>4} bytes): {}", payload.len(), hex_preview(payload)));
        }
        detail(&format!("received ({:>4} bytes): {}", payload_back.len(), hex_preview(payload_back)));
        if let Some(dns) = describe_dns(payload_back) {
            detail(&format!("decoded as DNS response: {dns}"));
        }
        Ok(())
    })
    .await?;

    // The request stream must stay open for the tunnel's lifetime; dropping it
    // here tears the tunnel down and closes the endpoint cleanly.
    Ok(())
}

fn server_name_or_host(common: &Common) -> String {
    common
        .server_name
        .clone()
        .unwrap_or_else(|| {
            let (host, _) = split_host_port(&common.proxy).expect("--proxy validated earlier");
            host
        })
}

fn proxy_port(common: &Common) -> anyhow::Result<u16> {
    let (_, port) = split_host_port(&common.proxy)?;
    Ok(port)
}

// ---------------------------------------------------------------------------
// Modes: plain TCP CONNECT (RFC 9114 §4.4) and WebSocket (RFC 9220)
// ---------------------------------------------------------------------------

/// Both TCP-family tunnels are the same byte pipe; they differ only in whether
/// the extended-CONNECT `:protocol` pseudo-header is present.
async fn run_tunnel(common: &Common, args: TunnelArgs, protocol: Option<Protocol>) -> anyhow::Result<()> {
    let label = match protocol {
        Some(_) => "ws (WebSocket over HTTP/3, RFC 9220)",
        None => "tcp (plain CONNECT, RFC 9114 §4.4)",
    };
    let (target_host, target_port) = split_host_port(&args.target)?;
    let payload = tunnel_payload(&args, &target_host, target_port)?;

    println!("=== mode: {label} ===");
    info(&format!("proxy            {}", common.proxy));
    info(&format!("tunnel target    {target_host}:{target_port}"));
    info(&format!(":protocol        {}", match &protocol {
        Some(p) => p.as_str().to_string(),
        None => "(absent - plain CONNECT)".to_string(),
    }));
    println!();

    let roots = load_roots(&common.ca)?;
    let mut proxy = check("handshake (QUIC + HTTP/3)", async {
        let (addr, name) = resolve_proxy(common).await?;
        detail(&format!("connected to {addr}, server name '{name}'"));
        Proxy::connect(addr, &name, roots, common.max_mtu).await
    })
    .await?;

    let result = tunnel_session(&mut proxy, common, &target_host, target_port, payload, protocol).await;
    proxy.close("masque-client done");
    result
}

fn tunnel_payload(
    args: &TunnelArgs,
    target_host: &str,
    target_port: u16,
) -> anyhow::Result<Vec<u8>> {
    Ok(match (&args.payload, &args.http_get) {
        (Some(p), _) => p.as_bytes().to_vec(),
        (None, Some(path)) => format!(
            "GET {path} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nUser-Agent: masque-client\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
        (None, None) => b"masque-client-hello".to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn tunnel_session(
    proxy: &mut Proxy,
    common: &Common,
    target_host: &str,
    target_port: u16,
    payload: Vec<u8>,
    protocol: Option<Protocol>,
) -> anyhow::Result<()> {
    // Unlike CONNECT-UDP, a plain CONNECT (and RFC 9220's WebSocket bootstrap)
    // takes its target from `:authority`, exactly like HTTP/1.1 CONNECT.
    let uri = format!("https://{}/", authority(target_host, target_port));
    detail(&format!("request :authority  {target_host}:{target_port}"));

    let mut req = request_for(uri, common)?;
    if let Some(p) = protocol {
        req.extensions_mut().insert(p);
    }

    let mut req_stream = check("CONNECT accepted", async {
        let mut stream = proxy
            .send_request
            .send_request(req)
            .await
            .context("send_request failed")?;
        let resp = stream.recv_response().await.context("recv_response failed")?;
        if resp.status() != StatusCode::OK {
            bail!("expected 200, got {} (auth missing? try --token)", resp.status());
        }
        detail(&format!("status 200; sent {} bytes", payload.len()));
        Ok(stream)
    })
    .await?;

    let reply = check("payload round-trip", async {
        req_stream
            .send_data(Bytes::copy_from_slice(&payload))
            .await
            .context("send_data failed")?;
        // Half-close the request body so the target observes EOF and responds.
        req_stream.finish().await.context("finish failed")?;

        let mut body = Vec::new();
        while let Some(mut chunk) = req_stream.recv_data().await.context("recv_data failed")? {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        if body.is_empty() {
            bail!("target sent nothing back (nothing was written through the tunnel)");
        }
        Ok(body)
    })
    .await?;

    if reply == payload {
        info("reply is an exact echo of the request payload");
    } else {
        info("reply is NOT an exact echo (target is not an echo server)");
        info(&format!("sent     ({:>4} bytes): {}", payload.len(), hex_preview(&payload)));
    }
    info(&format!("received ({:>4} bytes): {}", reply.len(), hex_preview(&reply)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Mode: CONNECT-IP (RFC 9484)
// ---------------------------------------------------------------------------

async fn run_ip(common: &Common, args: IpArgs) -> anyhow::Result<()> {
    println!("=== mode: ip (CONNECT-IP, RFC 9484) ===");
    info(&format!("proxy            {}", common.proxy));
    info("note             the SERVER needs root (CAP_NET_ADMIN); the client does not");
    println!();

    let roots = load_roots(&common.ca)?;
    let mut proxy = check("handshake (QUIC + HTTP/3)", async {
        let (addr, name) = resolve_proxy(common).await?;
        detail(&format!("connected to {addr}, server name '{name}'"));
        Proxy::connect(addr, &name, roots, common.max_mtu).await
    })
    .await?;

    let result = ip_session(&mut proxy, common, args.ping).await;
    proxy.close("masque-client done");
    result
}

async fn ip_session(
    proxy: &mut Proxy,
    common: &Common,
    ping: Option<Ipv4Addr>,
) -> anyhow::Result<()> {
    let proxy_authority = authority(&server_name_or_host(common), proxy_port(common)?);
    let uri = format!("https://{proxy_authority}{MASQUE_IP_PATH}");
    info(&format!("request :path      {MASQUE_IP_PATH}"));
    info("request :protocol  connect-ip");

    let mut req = request_for(uri, common)?;
    req.headers_mut()
        .insert("capsule-protocol", HeaderValue::from_static("?1"));
    // The locally patched h3 accepts arbitrary `:protocol` tokens; upstream
    // h3 0.0.8 only knows connect-udp/webtransport.
    req.extensions_mut().insert(
        Protocol::from_str("connect-ip").expect("patched h3 accepts connect-ip"),
    );

    let (mut req_stream, stream_id) = check("CONNECT-IP accepted", async {
        let mut stream = proxy
            .send_request
            .send_request(req)
            .await
            .context("send_request failed")?;
        let resp = stream.recv_response().await.context("recv_response failed")?;
        // Read the stream id BEFORE pulling any body: h3-quinn parks its
        // underlying RecvStream while a read is in flight, and asking for the id
        // at that moment panics inside its `recv_id()`.
        let stream_id = stream.id();
        if resp.status() != StatusCode::OK {
            bail!(
                "expected 200, got {} (auth missing? is the server on Linux and running as root?)",
                resp.status()
            );
        }
        detail("status 200, capsule-protocol: ?1");
        Ok((stream, stream_id))
    })
    .await?;

    // RFC 9484 §4.7: ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT arrive on the request
    // stream as RFC 9297 capsules (Type + Length + Value), never as datagrams.
    let signalling = check("signalling capsules", async {
        let mut pending = BytesMut::new();
        let mut assign: Option<Vec<capsule::AssignedAddress>> = None;
        let mut routes: Option<Vec<capsule::IpRange>> = None;

        while assign.is_none() || routes.is_none() {
            let mut chunk = tokio::time::timeout(CAPSULE_WAIT, req_stream.recv_data())
                .await
                .map_err(|_| anyhow!("no capsule within {CAPSULE_WAIT:?}"))?
                .context("recv_data failed")?
                .ok_or_else(|| anyhow!("request stream ended before both capsules arrived"))?;
            pending.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));

            // Cooperative-compose: keep the buffered remainder between frame
            // boundaries so a capsule split across chunks still decodes.
            let mut scanned = 0usize;
            while let Some((typ, value, used)) = capsule::split_capsule(&pending[scanned..]) {
                let value = value.to_vec();
                scanned += used;
                match typ {
                    capsule::CAPSULE_ADDRESS_ASSIGN => {
                        assign = Some(
                            capsule::decode_address_value(&value)
                                .ok_or_else(|| anyhow!("malformed ADDRESS_ASSIGN payload"))?,
                        );
                    }
                    capsule::CAPSULE_ROUTE_ADVERTISEMENT => {
                        routes = Some(
                            capsule::decode_route_value(&value)
                                .ok_or_else(|| anyhow!("malformed ROUTE_ADVERTISEMENT payload"))?,
                        );
                    }
                    _ => {}
                }
            }
            let _ = pending.split_to(scanned);
        }

        let assign = assign.ok_or_else(|| anyhow!("no ADDRESS_ASSIGN capsule"))?;
        let routes = routes.ok_or_else(|| anyhow!("no ROUTE_ADVERTISEMENT capsule"))?;
        Ok((assign, routes))
    })
    .await?;

    let (assign, routes) = signalling;
    let assigned = assign
        .first()
        .map(|a| (a.address, a.prefix_len))
        .ok_or_else(|| anyhow!("ADDRESS_ASSIGN carried no address"))?;
    info(&format!("ADDRESS_ASSIGN      {}/{}", assigned.0, assigned.1));
    info(&format!(
        "ROUTE_ADVERTISEMENT {} range(s){}",
        routes.len(),
        routes
            .first()
            .map(|r| format!(": {}..={} proto {}", r.start, r.end, r.ip_protocol))
            .unwrap_or_default()
    ));

    let client_v4 = match assigned.0 {
        IpAddr::V4(v4) => v4,
        other => bail!("this client only pings IPv4 assigned addresses, got {other}"),
    };

    // Default destination: the proxy's end of the point-to-point link. The pool
    // hands out /30 blocks (proxy = base+1, client = base+2), so the proxy is
    // the address immediately below the client's. Use --ping to override.
    let destination = match ping {
        Some(ip) => ip,
        None => {
            let mut octets = client_v4.octets();
            if octets[3] == 0 {
                bail!("cannot derive the proxy address from {client_v4}; pass --ping <ip>");
            }
            octets[3] -= 1;
            Ipv4Addr::from(octets)
        }
    };
    info(&format!("source (assigned)   {client_v4}"));
    info(&format!("ICMP echo request   {client_v4} -> {destination}"));

    let mut reader = proxy.h3.get_datagram_reader();
    let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
    tokio::spawn(async move {
        while let Ok(d) = reader.read_datagram().await {
            if d.stream_id() == stream_id && tx.send(d.into_payload()).is_err() {
                break;
            }
        }
    });

    let mut sender = proxy.h3.get_datagram_sender(stream_id);
    check("IP packet round-trip", async {
        // RFC 9484 §4.2: Context ID 0 (one 0x00 byte) + the RAW IP packet.
        let packet = icmpv4_echo_request(client_v4, destination, 0x1234, 1);
        let mut dgram = BytesMut::with_capacity(1 + packet.len());
        capsule::put_varint(&mut dgram, 0);
        dgram.extend_from_slice(&packet);
        sender
            .send_datagram(dgram.freeze())
            .map_err(|e| anyhow!("send_datagram failed: {e}"))?;

        // The tun device is a live interface as soon as it exists, so background
        // traffic the kernel emits onto it (IPv6 router solicitation, ...) can
        // reach the client before our echo reply. Drain everything that is not
        // the reply we asked for, rather than failing on the first packet.
        let deadline = tokio::time::Instant::now() + ROUNDTRIP_WAIT;
        let mut skipped: Vec<String> = Vec::new();
        loop {
            let reply = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .map_err(|_| {
                    let mut msg = format!("no ICMP echo reply within {ROUNDTRIP_WAIT:?}");
                    if !skipped.is_empty() {
                        msg.push_str(&format!(
                            " (skipped {} unrelated packet(s): {})",
                            skipped.len(),
                            skipped.join("; ")
                        ));
                    }
                    anyhow!(msg)
                })?
                .ok_or_else(|| anyhow!("datagram channel closed"))?;

            let pkt = match capsule::strip_context_id(&reply) {
                Some(p) => p,
                None => {
                    skipped.push(format!(
                        "datagram without Context ID 0: {:02x?}",
                        &reply[..reply.len().min(8)]
                    ));
                    continue;
                }
            };
            match match_echo_reply(pkt, destination) {
                Ok(what) => {
                    if !skipped.is_empty() {
                        detail(&format!("skipped {} unrelated downlink packet(s):", skipped.len()));
                        for why in &skipped {
                            detail(why);
                        }
                    }
                    detail(&what);
                    break;
                }
                Err(why) => skipped.push(why),
            }
        }

        Ok(())
    })
    .await?;

    Ok(())
}

/// Does `pkt` carry the ICMP echo reply we asked for, from `src`? Returns a
/// description of it on success, or the reason it does not match on failure.
fn match_echo_reply(pkt: &[u8], src: Ipv4Addr) -> Result<String, String> {
    if pkt.len() < 28 {
        return Err(format!("{}-byte packet, too short for IPv4+ICMP", pkt.len()));
    }
    if pkt[0] >> 4 != 4 {
        return Err(format!(
            "non-IPv4 downlink packet (version nibble {}): {}",
            pkt[0] >> 4,
            hex_preview(pkt)
        ));
    }
    if pkt[9] != 1 {
        return Err(format!("IPv4 protocol {} is not ICMP (1)", pkt[9]));
    }
    let from = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let to = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    if pkt[20] != 0 {
        return Err(format!("ICMP type {} from {from} is not an echo reply", pkt[20]));
    }
    if u16::from_be_bytes([pkt[24], pkt[25]]) != 0x1234 {
        return Err(format!("echo reply from {from} with an unexpected identifier"));
    }
    if from != src {
        return Err(format!("echo reply came from {from}, expected {src}"));
    }
    Ok(format!(
        "ICMP echo reply: IPv4 {from} -> {to}, type 0 (echo reply), {} bytes",
        pkt.len()
    ))
}

// ---------------------------------------------------------------------------
// Packet helpers (deliberately local: nothing here is shared with the server)
// ---------------------------------------------------------------------------

/// Build an ICMPv4 echo request (`src -> dst`) as a raw IPv4 packet with correct
/// IP and ICMP checksums.
fn icmpv4_echo_request(src: Ipv4Addr, dst: Ipv4Addr, ident: u16, seq: u16) -> Vec<u8> {
    let payload = b"masque-client-connect-ip-ping";
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(8); // type: echo request
    icmp.push(0); // code
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&ident.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let icmp_sum = ip_checksum(&icmp);
    icmp[2..4].copy_from_slice(&icmp_sum.to_be_bytes());

    let total = 20 + icmp.len();
    let mut ip = Vec::with_capacity(total);
    ip.push(0x45); // version 4, IHL 5
    ip.push(0); // DSCP/ECN
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0]); // identification
    ip.extend_from_slice(&[0, 0]); // flags / fragment offset
    ip.push(64); // TTL
    ip.push(1); // protocol: ICMP
    ip.extend_from_slice(&[0, 0]); // checksum placeholder
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ip_sum = ip_checksum(&ip);
    ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// RFC 1071 internet checksum (16-bit one's complement sum).
fn ip_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A minimal DNS `A` query for `name` (RD set), ready to be tunnelled.
fn dns_query(name: &str) -> Vec<u8> {
    // Transaction ID: nothing security-sensitive, just needs to vary.
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0x1234);
    let mut q = Vec::with_capacity(16 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root label: end of QNAME
    q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    q
}

/// Render as much of `bytes` as will fit on one detail line.
fn hex_preview(bytes: &[u8]) -> String {
    const MAX: usize = 24;
    let shown = &bytes[..bytes.len().min(MAX)];
    let mut s = shown
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    if bytes.len() > MAX {
        s.push_str(&format!(" ... (+{} bytes)", bytes.len() - MAX));
    }
    s
}

/// Try to interpret `bytes` as a DNS response. Returns `None` if it clearly is
/// not one (too short, or the QR bit is unset — e.g. an echo server bounced our
/// query straight back).
fn describe_dns(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
    let mut off = 12usize;
    for _ in 0..qdcount {
        if consume_name(bytes, &mut off).is_none() || off + 4 > bytes.len() {
            return None;
        }
        off += 4; // QTYPE + QCLASS
    }
    let mut answers = Vec::new();
    for _ in 0..ancount {
        consume_name(bytes, &mut off)?;
        if off + 10 > bytes.len() {
            return None;
        }
        let typ = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
        let rdlen = u16::from_be_bytes([bytes[off + 8], bytes[off + 9]]) as usize;
        off += 10;
        if off + rdlen > bytes.len() {
            return None;
        }
        if typ == 1 && rdlen == 4 {
            answers.push(Ipv4Addr::new(bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]).to_string());
        } else if typ == 28 && rdlen == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[off..off + 16]);
            answers.push(Ipv6Addr::from(octets).to_string());
        } else {
            answers.push(format!("type {typ}"));
        }
        off += rdlen;
    }
    Some(format!(
        "id={id:#06x} rcode={} answers={}",
        flags & 0xf,
        if answers.is_empty() {
            "(none)".to_string()
        } else {
            answers.join(", ")
        }
    ))
}

/// Skip one DNS name at `off`, handling compression pointers.
fn consume_name(bytes: &[u8], off: &mut usize) -> Option<()> {
    loop {
        let len = *bytes.get(*off)?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    *off += 1;
                    return Some(());
                }
                *off += 1 + len as usize;
            }
            // A compression pointer is 2 bytes and terminates the name.
            _ => {
                *off += 2;
                return Some(());
            }
        }
    }
}

/// Parse an even-length hex string into bytes.
fn parse_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if !compact.len().is_multiple_of(2) {
        bail!("hex string must have an even number of digits, got {}", compact.len());
    }
    if compact.is_empty() {
        bail!("hex string is empty");
    }
    (0..compact.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&compact[i..i + 2], 16)
                .with_context(|| format!("not hex: '{}'", &compact[i..i + 2]))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a throwaway self-signed CA cert with openssl (the same tool the
    /// e2e tests use). Returns `None` to skip cert-dependent scenarios when
    /// openssl is unavailable.
    fn gen_ca(dir: &std::path::Path) -> Option<PathBuf> {
        let key = dir.join("test-ca.key.pem");
        let cert = dir.join("test-ca.cert.pem");
        let ok = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key.to_str()?,
                "-out",
                cert.to_str()?,
                "-days",
                "1",
                "-subj",
                "/CN=masque-client-test-ca",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?
            .success();
        ok.then_some(cert)
    }

    /// `load_roots` merges the "system" store (pinned via SSL_CERT_FILE /
    /// SSL_CERT_DIR, which rustls-native-certs honours) with `--ca` PEMs, and
    /// only bails when the combined store is empty.
    ///
    /// Env vars are mutated, so this must not run in parallel with anything
    /// else that touches them — it is the only test in this binary.
    #[test]
    fn load_roots_merges_system_store_and_ca_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty_file = dir.path().join("empty.pem");
        std::fs::write(&empty_file, "").expect("write empty pem");
        let empty_dir = dir.path().join("empty-dir");
        std::fs::create_dir(&empty_dir).expect("mkdir");
        let ca = gen_ca(dir.path());

        // SAFETY: single test thread mutates these; nothing else in this
        // binary's test suite reads them.
        unsafe {
            std::env::set_var("SSL_CERT_FILE", &empty_file);
            std::env::set_var("SSL_CERT_DIR", &empty_dir);
        }

        // Empty "system" store and no --ca: the combined store is empty -> bail.
        assert!(load_roots(&[]).is_err(), "empty system + no --ca must bail");

        // A --ca PEM alone is enough, and lands in the store.
        if let Some(ca) = &ca {
            let roots = load_roots(std::slice::from_ref(ca)).expect("--ca alone must load");
            assert_eq!(roots.len(), 1, "--ca anchor missing from the store");
        }

        // The "system" store alone is enough: point SSL_CERT_FILE at the CA.
        if let Some(ca) = &ca {
            unsafe { std::env::set_var("SSL_CERT_FILE", ca) };
            let roots = load_roots(&[]).expect("system store alone must load");
            assert_eq!(roots.len(), 1, "system anchor missing from the store");

            // Merge: the same anchor via both paths -> two entries, no bail.
            let roots = load_roots(std::slice::from_ref(ca)).expect("merge must load");
            assert_eq!(roots.len(), 2, "system + --ca anchors must coexist");
        }

        unsafe {
            std::env::remove_var("SSL_CERT_FILE");
            std::env::remove_var("SSL_CERT_DIR");
        }
    }
}
