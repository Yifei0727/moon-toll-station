use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use anyhow::{Context, anyhow, bail};
use hickory_resolver::{
    TokioAsyncResolver,
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use tracing::{debug, info, warn};

use crate::config::AppConfig;

/// Returns `true` if `ip` belongs to an RFC 6890 IPv4/IPv6 special-purpose
/// address range. These addresses must never be proxied to, whether the
/// target was supplied directly or resolved from a domain name.
fn is_rfc6890_special(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_rfc6890_special_v4(ipv4),
        IpAddr::V6(ipv6) => is_rfc6890_special_v6(ipv6),
    }
}

fn is_rfc6890_special_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();

    // "This" network 0.0.0.0/8 (RFC 1122) — source-only, never a valid target.
    if o[0] == 0 {
        return true;
    }
    // IETF protocol assignments 192.0.0.0/24 (RFC 6890), which covers the
    // smaller delegated blocks (192.0.0.0/29, 192.0.0.8/32, 192.0.0.9/32,
    // 192.0.0.10/32, 192.0.0.170/32, 192.0.0.171/32, etc.).
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return true;
    }
    // Shared address space / CGNAT 100.64.0.0/10 (RFC 6598).
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return true;
    }

    ip.is_unspecified()      // 0.0.0.0/32
        || ip.is_loopback()  // 127.0.0.0/8
        || ip.is_private()   // 10/8, 172.16/12, 192.168/16 (RFC 1918)
        || ip.is_link_local() // 169.254.0.0/16
        || ip.is_multicast() // 224.0.0.0/4
        || ip.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || (o[0] == 198 && (18..=19).contains(&o[1])) // 198.18.0.0/15 benchmark (RFC 2544)
        || o[0] >= 240       // 240.0.0.0/4 reserved (RFC 1112), incl. 255.255.255.255
}

fn is_rfc6890_special_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_unique_local() // fc00::/7 (IPv6 private)
        || ip.is_unicast_link_local() // fe80::/10
        || ip.is_multicast()    // ff00::/8
        || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
}

const HTTP_HEADER_MAX_LEN: usize = 8192;
const SOCKS4_FIELD_MAX_LEN: usize = 1024;
const PROBE_LEN: usize = 512;
const UDP_PACKET_MAX_LEN: usize = 65535;

#[derive(Debug, Clone)]
pub struct ProxyServer {
    config: AppConfig,
    resolver: Resolver,
}

impl ProxyServer {
    pub fn new(config: AppConfig) -> anyhow::Result<Self> {
        let resolver = Resolver::new(config.dns_server)?;
        Ok(Self { config, resolver })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.config.listen)
            .await
            .with_context(|| format!("failed to bind {}", self.config.listen))?;

        info!(
            listen = %self.config.listen,
            dns_server = ?self.config.dns_server,
            "proxy server started"
        );

        loop {
            let (stream, peer_addr) = listener.accept().await.context("accept failed")?;
            let resolver = self.resolver.clone();
            let config = self.config.clone();

            tokio::spawn(async move {
                if let Err(err) = handle_client(stream, peer_addr, resolver, config).await {
                    warn!(peer = %peer_addr, error = %err, "client session ended with error");
                }
            });
        }
    }
}

#[derive(Debug, Clone)]
struct Resolver {
    inner: TokioAsyncResolver,
}

impl Resolver {
    fn new(dns_server: Option<SocketAddr>) -> anyhow::Result<Self> {
        let inner = match dns_server {
            Some(server) => {
                let nameservers =
                    NameServerConfigGroup::from_ips_clear(&[server.ip()], server.port(), true);
                let resolver_config = ResolverConfig::from_parts(None, vec![], nameservers);
                TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default())
            }
            None => {
                TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default())
            }
        };
        Ok(Self { inner })
    }

    async fn resolve_first(&self, host: &str, port: u16) -> anyhow::Result<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }

        let response = self
            .inner
            .lookup_ip(host)
            .await
            .with_context(|| format!("dns lookup failed for {host}"))?;

        let ip = response
            .iter()
            .next()
            .ok_or_else(|| anyhow!("dns response was empty for {host}"))?;

        Ok(SocketAddr::new(ip, port))
    }
}

#[derive(Debug, Clone, Copy)]
enum Protocol {
    Socks4,
    Socks5,
    HttpConnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Host {
    Ip(IpAddr),
    Name(String),
}

impl Host {
    async fn resolve(&self, resolver: &Resolver, port: u16) -> anyhow::Result<SocketAddr> {
        match self {
            Host::Ip(ip) => Ok(SocketAddr::new(*ip, port)),
            Host::Name(name) => resolver.resolve_first(name, port).await,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Ip(ip) => write!(f, "{ip}"),
            Host::Name(name) => write!(f, "{name}"),
        }
    }
}

fn format_target(peer_addr: SocketAddr, destination: Option<(&Host, u16)>) -> String {
    match destination {
        Some((Host::Ip(IpAddr::V6(ip)), port)) => format!("<{peer_addr},[{ip}]:{port}>"),
        Some((host, port)) => format!("<{peer_addr},{host}:{port}>"),
        None => format!("<{peer_addr},None>"),
    }
}

async fn handle_client(
    client: TcpStream,
    peer_addr: SocketAddr,
    resolver: Resolver,
    config: AppConfig,
) -> anyhow::Result<()> {
    info!(target = %format_target(peer_addr, None), "request target");
    let mut probe = [0_u8; PROBE_LEN];
    let read_n = timeout(config.handshake_timeout(), client.peek(&mut probe))
        .await
        .context("handshake probe timeout")?
        .context("handshake probe failed")?;

    if read_n == 0 {
        bail!("client closed before handshake");
    }

    let protocol = detect_protocol(&probe[..read_n]).ok_or_else(|| anyhow!("unknown protocol"))?;
    debug!(peer = %peer_addr, protocol = ?protocol, "protocol detected");

    match protocol {
        Protocol::Socks4 => handle_socks4(client, peer_addr, resolver, &config).await,
        Protocol::Socks5 => handle_socks5(client, peer_addr, resolver, &config).await,
        Protocol::HttpConnect => handle_http_connect(client, peer_addr, resolver, &config).await,
    }
}

fn detect_protocol(data: &[u8]) -> Option<Protocol> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        0x04 => Some(Protocol::Socks4),
        0x05 => Some(Protocol::Socks5),
        _ => {
            if data.starts_with(b"CONNECT ") {
                Some(Protocol::HttpConnect)
            } else {
                None
            }
        }
    }
}

async fn handle_socks5(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    resolver: Resolver,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let mut header = [0_u8; 2];
    client.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        bail!("invalid SOCKS5 version byte");
    }
    let method_len = header[1] as usize;
    let mut methods = vec![0_u8; method_len];
    client.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xFF]).await?;
        bail!("SOCKS5 no-auth method not offered");
    }
    client.write_all(&[0x05, 0x00]).await?;

    let mut req_head = [0_u8; 4];
    client.read_exact(&mut req_head).await?;
    if req_head[0] != 0x05 {
        bail!("invalid SOCKS5 request version");
    }
    if req_head[2] != 0x00 {
        send_socks5_reply(
            &mut client,
            0x01,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )
        .await?;
        bail!("invalid SOCKS5 reserved byte {}", req_head[2]);
    }
    let cmd = req_head[1];
    let (host, port) = match read_socks5_target_from_stream(&mut client, req_head[3]).await {
        Ok(target) => target,
        Err(err) => {
            send_socks5_reply(
                &mut client,
                0x08,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
            .await?;
            return Err(err);
        }
    };
    info!(
        target = %format_target(peer_addr, Some((&host, port))),
        "request target"
    );

    match cmd {
        0x01 => handle_socks5_connect(client, resolver, config, host, port).await,
        0x02 => handle_socks5_bind(client, resolver, config, host, port).await,
        0x03 => handle_socks5_udp_associate(client, peer_addr, resolver, config, host, port).await,
        _ => {
            send_socks5_reply(
                &mut client,
                0x07,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
            .await?;
            bail!("unsupported SOCKS5 command {cmd}");
        }
    }
}

async fn handle_socks5_bind(
    mut client: TcpStream,
    resolver: Resolver,
    config: &AppConfig,
    host: Host,
    port: u16,
) -> anyhow::Result<()> {
    let expected_peer = host.resolve(&resolver, port).await?;
    if config.block_special_addrs() && is_rfc6890_special(expected_peer.ip()) {
        send_socks5_reply(
            &mut client,
            0x02, // connection not allowed by ruleset
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )
        .await?;
        bail!("SOCKS5 BIND blocked: target IP {} is a special-purpose (RFC 6890) address", expected_peer.ip());
    }
    let bind_addr = match expected_peer.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::from([0_u8; 16]), 0),
    };
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("SOCKS5 BIND listen failed")?;
    let local_bind = listener
        .local_addr()
        .context("failed to read SOCKS5 BIND local addr")?;
    send_socks5_reply(&mut client, 0x00, local_bind).await?;

    let accept_result = timeout(config.connect_timeout(), listener.accept())
        .await
        .context("SOCKS5 BIND accept timeout")?;
    let (mut upstream, accepted_addr) = accept_result.context("SOCKS5 BIND accept failed")?;
    if accepted_addr.ip() != expected_peer.ip() {
        send_socks5_reply(
            &mut client,
            0x02,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )
        .await?;
        bail!(
            "SOCKS5 BIND accepted unexpected peer: expected {}, got {}",
            expected_peer.ip(),
            accepted_addr.ip()
        );
    }

    send_socks5_reply(&mut client, 0x00, accepted_addr).await?;
    tunnel(&mut client, &mut upstream).await
}

async fn handle_socks5_connect(
    mut client: TcpStream,
    resolver: Resolver,
    config: &AppConfig,
    host: Host,
    port: u16,
) -> anyhow::Result<()> {
    let target_addr = host.resolve(&resolver, port).await?;
    if config.block_special_addrs() && is_rfc6890_special(target_addr.ip()) {
        send_socks5_reply(
            &mut client,
            0x02, // connection not allowed by ruleset
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )
        .await?;
        bail!("SOCKS5 connection blocked: target IP {} is a special-purpose (RFC 6890) address", target_addr.ip());
    }
    let connect_result = timeout(config.connect_timeout(), TcpStream::connect(target_addr))
        .await
        .context("SOCKS5 connect timeout")?;

    let mut upstream = match connect_result {
        Ok(stream) => stream,
        Err(err) => {
            send_socks5_reply(
                &mut client,
                0x05,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
            .await?;
            return Err(err).context("SOCKS5 upstream connect failed");
        }
    };

    let local = upstream
        .local_addr()
        .context("failed to get local bind addr")?;
    send_socks5_reply(&mut client, 0x00, local).await?;
    tunnel(&mut client, &mut upstream).await
}

async fn handle_socks5_udp_associate(
    mut control: TcpStream,
    peer_addr: SocketAddr,
    resolver: Resolver,
    config: &AppConfig,
    requested_host: Host,
    requested_port: u16,
) -> anyhow::Result<()> {
    let control_local = control
        .local_addr()
        .context("failed to read control socket local addr")?;
    let udp_bind_addr = match control_local.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::from([0_u8; 16]), 0),
    };
    let udp_socket = UdpSocket::bind(udp_bind_addr)
        .await
        .context("failed to bind UDP relay socket")?;
    let udp_local = udp_socket
        .local_addr()
        .context("failed to read UDP relay local addr")?;
    let reply_addr = SocketAddr::new(control_local.ip(), udp_local.port());
    send_socks5_reply(&mut control, 0x00, reply_addr).await?;

    // The client address is learned per-packet: any source that sends a
    // well-formed SOCKS5 UDP request (RSV=0, FRAG=0) is the client. This lets
    // QUIC clients migrate their source address (RFC 9000 §9) without the relay
    // misrouting their packets as upstream responses. The original code locked
    // `client_udp_addr` to the first source, which broke migration.
    let mut client_udp_addr: Option<SocketAddr> = match requested_host {
        Host::Ip(ip) if requested_port != 0 => Some(SocketAddr::new(ip, requested_port)),
        _ => None,
    };
    // Cache resolved targets so DNS resolution + RFC 6890 checks run once per
    // destination instead of on every datagram. A UDP relay must not add
    // RTT-scale latency/jitter to each packet — QUIC's loss recovery is
    // sensitive to it.
    let mut target_cache: HashMap<(Host, u16), SocketAddr> = HashMap::new();
    let mut udp_buf = vec![0_u8; UDP_PACKET_MAX_LEN];
    let mut control_buf = [0_u8; 1];
    loop {
        tokio::select! {
            read_result = control.read(&mut control_buf) => {
                let read_n = read_result.context("failed reading SOCKS5 UDP control channel")?;
                if read_n == 0 {
                    debug!("SOCKS5 UDP control channel closed");
                    break;
                }
                debug!(read_n, "unexpected bytes on SOCKS5 UDP control channel");
            }
            recv_result = udp_socket.recv_from(&mut udp_buf) => {
                let (packet_len, source_addr) = match recv_result {
                    Ok(x) => x,
                    Err(err) => {
                        debug!(peer = %peer_addr, error = %err, "UDP relay recv_from failed");
                        continue;
                    }
                };

                // A client packet is a SOCKS5 UDP request wrapping the real
                // payload (e.g. a QUIC datagram). A raw QUIC datagram from the
                // upstream fails the SOCKS5 RSV check, so it is treated as a
                // response. Distinguishing client vs upstream by *content* (not
                // source address) is what makes QUIC connection migration safe.
                match parse_socks5_udp_request(&udp_buf[..packet_len]) {
                    Ok((host, port, payload, frag)) => {
                        if frag != 0 {
                            debug!(peer = %peer_addr, frag, "dropping fragmented SOCKS5 UDP packet");
                            continue;
                        }
                        client_udp_addr = Some(source_addr);
                        let payload = payload.to_vec();
                        let target = match target_cache.get(&(host.clone(), port)) {
                            Some(t) => *t,
                            None => {
                                let t = match host.resolve(&resolver, port).await {
                                    Ok(t) => t,
                                    Err(err) => {
                                        debug!(peer = %peer_addr, error = %err, "SOCKS5 UDP relay target resolution failed");
                                        continue;
                                    }
                                };
                                if config.block_special_addrs() && is_rfc6890_special(t.ip()) {
                                    debug!(target = %t, "SOCKS5 UDP relay blocked target IP: special-purpose (RFC 6890) address");
                                    continue;
                                }
                                target_cache.insert((host.clone(), port), t);
                                t
                            }
                        };
                        if let Err(err) = udp_socket.send_to(&payload, target).await {
                            debug!(peer = %peer_addr, target = %target, error = %err, "UDP relay send_to target failed");
                            continue;
                        }
                    }
                    Err(_) => {
                        // Not a SOCKS5 UDP request -> upstream response; relay
                        // it back to the client. A single dropped datagram must
                        // not tear down the whole session, so send errors are
                        // logged and skipped instead of propagated.
                        if let Some(client_addr) = client_udp_addr {
                            let response = build_socks5_udp_response(source_addr, &udp_buf[..packet_len]);
                            if let Err(err) = udp_socket.send_to(&response, client_addr).await {
                                debug!(peer = %peer_addr, client = %client_addr, error = %err, "UDP relay send_to client failed");
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn read_socks5_target_from_stream(
    stream: &mut TcpStream,
    atyp: u8,
) -> anyhow::Result<(Host, u16)> {
    let host = read_socks5_host_from_stream(stream, atyp).await?;
    let mut port_raw = [0_u8; 2];
    stream.read_exact(&mut port_raw).await?;
    let port = u16::from_be_bytes(port_raw);
    Ok((host, port))
}

async fn read_socks5_host_from_stream(stream: &mut TcpStream, atyp: u8) -> anyhow::Result<Host> {
    match atyp {
        0x01 => {
            let mut raw = [0_u8; 4];
            stream.read_exact(&mut raw).await?;
            Ok(Host::Ip(IpAddr::V4(Ipv4Addr::from(raw))))
        }
        0x04 => {
            let mut raw = [0_u8; 16];
            stream.read_exact(&mut raw).await?;
            Ok(Host::Ip(IpAddr::from(raw)))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut raw = vec![0_u8; len[0] as usize];
            stream.read_exact(&mut raw).await?;
            let domain = String::from_utf8(raw).context("invalid SOCKS5 domain")?;
            Ok(Host::Name(domain))
        }
        _ => bail!("unsupported SOCKS5 address type {atyp}"),
    }
}

fn parse_socks5_udp_request(packet: &[u8]) -> anyhow::Result<(Host, u16, &[u8], u8)> {
    if packet.len() < 4 {
        bail!("SOCKS5 UDP packet too short");
    }
    if packet[0] != 0 || packet[1] != 0 {
        bail!("SOCKS5 UDP packet has invalid RSV");
    }
    let frag = packet[2];

    let (host, addr_end) = parse_socks5_host_from_bytes(packet[3], &packet[4..])?;
    let port_slice = packet
        .get(addr_end + 4..addr_end + 6)
        .ok_or_else(|| anyhow!("SOCKS5 UDP packet missing destination port"))?;
    let port = u16::from_be_bytes([port_slice[0], port_slice[1]]);
    let payload = packet
        .get(addr_end + 6..)
        .ok_or_else(|| anyhow!("SOCKS5 UDP packet missing payload"))?;

    Ok((host, port, payload, frag))
}

fn parse_socks5_host_from_bytes(atyp: u8, data: &[u8]) -> anyhow::Result<(Host, usize)> {
    match atyp {
        0x01 => {
            let raw = data
                .get(..4)
                .ok_or_else(|| anyhow!("SOCKS5 IPv4 address is truncated"))?;
            Ok((
                Host::Ip(IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))),
                4,
            ))
        }
        0x04 => {
            let raw = data
                .get(..16)
                .ok_or_else(|| anyhow!("SOCKS5 IPv6 address is truncated"))?;
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(raw);
            Ok((Host::Ip(IpAddr::from(octets)), 16))
        }
        0x03 => {
            let domain_len = *data
                .first()
                .ok_or_else(|| anyhow!("SOCKS5 domain length is missing"))?
                as usize;
            let domain_raw = data
                .get(1..1 + domain_len)
                .ok_or_else(|| anyhow!("SOCKS5 domain bytes are truncated"))?;
            let domain =
                String::from_utf8(domain_raw.to_vec()).context("invalid UTF-8 SOCKS5 domain")?;
            Ok((Host::Name(domain), 1 + domain_len))
        }
        _ => bail!("unsupported SOCKS5 UDP address type {atyp}"),
    }
}

fn build_socks5_udp_response(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 1 + 16 + 2 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    match source.ip() {
        IpAddr::V4(ip) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&source.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

async fn send_socks5_reply(
    client: &mut TcpStream,
    rep: u8,
    bound: SocketAddr,
) -> anyhow::Result<()> {
    let mut reply = vec![0x05, rep, 0x00];
    match bound.ip() {
        IpAddr::V4(ip) => {
            reply.push(0x01);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(0x04);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&bound.port().to_be_bytes());
    client.write_all(&reply).await?;
    Ok(())
}

async fn handle_socks4(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    resolver: Resolver,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let mut req = [0_u8; 8];
    client.read_exact(&mut req).await?;
    if req[0] != 0x04 {
        bail!("invalid SOCKS4 version byte");
    }
    if req[1] != 0x01 {
        send_socks4_reply(&mut client, 0x5B).await?;
        bail!("unsupported SOCKS4 command {}", req[1]);
    }
    let port = u16::from_be_bytes([req[2], req[3]]);
    let ip = [req[4], req[5], req[6], req[7]];

    let _userid = read_null_terminated(&mut client, SOCKS4_FIELD_MAX_LEN)
        .await
        .context("failed to read SOCKS4 user id")?;

    let host = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        let domain = read_null_terminated(&mut client, SOCKS4_FIELD_MAX_LEN)
            .await
            .context("failed to read SOCKS4a domain")?;
        Host::Name(String::from_utf8(domain).context("invalid SOCKS4a domain")?)
    } else {
        Host::Ip(IpAddr::V4(Ipv4Addr::from(ip)))
    };
    info!(
        target = %format_target(peer_addr, Some((&host, port))),
        "request target"
    );

    let target_addr = host.resolve(&resolver, port).await?;
    if config.block_special_addrs() && is_rfc6890_special(target_addr.ip()) {
        send_socks4_reply(&mut client, 0x5B).await?; // request rejected
        bail!("SOCKS4 connection blocked: target IP {} is a special-purpose (RFC 6890) address", target_addr.ip());
    }
    let connect_result = timeout(config.connect_timeout(), TcpStream::connect(target_addr))
        .await
        .context("SOCKS4 connect timeout")?;

    let mut upstream = match connect_result {
        Ok(stream) => stream,
        Err(err) => {
            send_socks4_reply(&mut client, 0x5B).await?;
            return Err(err).context("SOCKS4 upstream connect failed");
        }
    };

    send_socks4_reply(&mut client, 0x5A).await?;
    tunnel(&mut client, &mut upstream).await
}

async fn send_socks4_reply(client: &mut TcpStream, status: u8) -> anyhow::Result<()> {
    client
        .write_all(&[0x00, status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;
    Ok(())
}

async fn read_null_terminated(stream: &mut TcpStream, max_len: usize) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        if out.len() >= max_len {
            bail!("null-terminated field exceeds max length");
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        if byte[0] == 0 {
            break;
        }
        out.push(byte[0]);
    }
    Ok(out)
}

async fn handle_http_connect(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    resolver: Resolver,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let (head, pending_payload) = read_http_head(&mut client).await?;
    let request = std::str::from_utf8(&head).context("HTTP request is not valid UTF-8")?;
    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| anyhow!("HTTP request missing request line"))?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let authority = parts.next().unwrap_or_default();
    let _version = parts.next().unwrap_or_default();

    if method != "CONNECT" {
        client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            .await?;
        bail!("unsupported HTTP method: {method}");
    }

    let (host, port) = parse_authority(authority)?;
    info!(
        target = %format_target(peer_addr, Some((&host, port))),
        "request target"
    );
    let target_addr = host.resolve(&resolver, port).await?;
    if config.block_special_addrs() && is_rfc6890_special(target_addr.ip()) {
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            .await?;
        bail!("HTTP CONNECT connection blocked: target IP {} is a special-purpose (RFC 6890) address", target_addr.ip());
    }
    let connect_result = timeout(config.connect_timeout(), TcpStream::connect(target_addr))
        .await
        .context("HTTP CONNECT upstream connect timeout")?;

    let mut upstream = match connect_result {
        Ok(stream) => stream,
        Err(err) => {
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await?;
            return Err(err).context("HTTP CONNECT upstream connect failed");
        }
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    if !pending_payload.is_empty() {
        upstream.write_all(&pending_payload).await?;
    }

    tunnel(&mut client, &mut upstream).await
}

async fn read_http_head(stream: &mut TcpStream) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut buffer = Vec::with_capacity(1024);
    loop {
        if buffer.len() > HTTP_HEADER_MAX_LEN {
            bail!("HTTP header exceeds max allowed length");
        }

        let mut chunk = [0_u8; 1024];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before HTTP header completed");
        }

        buffer.extend_from_slice(&chunk[..n]);

        if let Some(idx) = find_subsequence(&buffer, b"\r\n\r\n") {
            let head_end = idx + 4;
            let head = buffer[..head_end].to_vec();
            let pending = buffer[head_end..].to_vec();
            return Ok((head, pending));
        }
    }
}

fn find_subsequence(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len())
        .position(|window| window == needle)
}

fn parse_authority(authority: &str) -> anyhow::Result<(Host, u16)> {
    if authority.is_empty() {
        bail!("empty CONNECT authority");
    }

    if authority.starts_with('[') {
        let host_end = authority
            .find(']')
            .ok_or_else(|| anyhow!("invalid bracketed IPv6 CONNECT authority"))?;
        let host = &authority[1..host_end];
        let remainder = authority
            .get(host_end + 1..)
            .ok_or_else(|| anyhow!("missing CONNECT authority suffix"))?;
        let port_part = remainder
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("missing port delimiter in CONNECT authority"))?;
        let ip: IpAddr = host.parse().context("invalid IPv6 in CONNECT authority")?;
        let port: u16 = port_part.parse().context("invalid CONNECT port")?;
        return Ok((Host::Ip(ip), port));
    }

    let (host_part, port_part) = authority
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("CONNECT authority must be host:port"))?;
    let port: u16 = port_part.parse().context("invalid CONNECT port")?;
    if let Ok(ip) = host_part.parse::<IpAddr>() {
        Ok((Host::Ip(ip), port))
    } else {
        Ok((Host::Name(host_part.to_string()), port))
    }
}

async fn tunnel(client: &mut TcpStream, upstream: &mut TcpStream) -> anyhow::Result<()> {
    let (from_client, from_upstream) = copy_bidirectional(client, upstream)
        .await
        .context("tunnel copy failed")?;
    debug!(
        from_client = from_client,
        from_upstream = from_upstream,
        "tunnel closed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Host, Protocol, build_socks5_udp_response, detect_protocol, parse_authority,
        parse_socks5_udp_request,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn detects_protocol_by_first_bytes() {
        assert!(matches!(
            detect_protocol(&[0x05, 0x01]),
            Some(Protocol::Socks5)
        ));
        assert!(matches!(
            detect_protocol(&[0x04, 0x01]),
            Some(Protocol::Socks4)
        ));
        assert!(matches!(
            detect_protocol(b"CONNECT example.com:443 HTTP/1.1\r\n"),
            Some(Protocol::HttpConnect)
        ));
        assert!(detect_protocol(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn parses_connect_authority() {
        let (host, port) = parse_authority("127.0.0.1:8080").expect("parse ipv4");
        match host {
            super::Host::Ip(IpAddr::V4(ip)) => assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1)),
            _ => panic!("expected ipv4 host"),
        }
        assert_eq!(port, 8080);

        let (host, port) = parse_authority("[::1]:443").expect("parse ipv6");
        match host {
            super::Host::Ip(IpAddr::V6(ip)) => assert_eq!(ip, Ipv6Addr::LOCALHOST),
            _ => panic!("expected ipv6 host"),
        }
        assert_eq!(port, 443);

        let (_host, port) = parse_authority("example.com:8443").expect("parse domain");
        assert_eq!(port, 8443);
    }

    #[test]
    fn parses_and_builds_socks5_udp_packets() {
        let request = [
            0x00, 0x00, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x01, 0xbb, 0xde, 0xad, 0xbe, 0xef,
        ];
        let (host, port, payload, frag) =
            parse_socks5_udp_request(&request).expect("parse udp request");
        match host {
            Host::Name(name) => assert_eq!(name, "example.com"),
            _ => panic!("expected domain host"),
        }
        assert_eq!(frag, 0);
        assert_eq!(port, 443);
        assert_eq!(payload, [0xde, 0xad, 0xbe, 0xef]);

        let response =
            build_socks5_udp_response("1.2.3.4:5300".parse().expect("parse source"), &[0xaa, 0xbb]);
        assert_eq!(response[0..4], [0x00, 0x00, 0x00, 0x01]);
        assert_eq!(response[4..8], [1, 2, 3, 4]);
        assert_eq!(response[8..10], 5300_u16.to_be_bytes());
        assert_eq!(response[10..], [0xaa, 0xbb]);
    }

    #[test]
    fn test_is_rfc6890_special() {
        use super::is_rfc6890_special;

        // RFC 6890 special-purpose addresses that must be blocked.
        let blocked = [
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),       // 0.0.0.0/32
            IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3)),       // "this" network 0.0.0.0/8
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),      // 10.0.0.0/8 private
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),    // 100.64.0.0/10 CGNAT
            IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255)), // 100.64.0.0/10 edge
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),     // 127.0.0.0/8 loopback
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),   // 169.254.0.0/16 link-local
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),    // 172.16.0.0/12 private
            IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0)),     // 192.0.0.0/24 IETF
            IpAddr::V4(Ipv4Addr::new(192, 0, 0, 170)),   // NAT64 discovery
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),     // 192.0.2.0/24 TEST-NET-1
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),   // 192.168.0.0/16 private
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),    // 198.18.0.0/15 benchmark
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),  // 198.51.100.0/24 TEST-NET-2
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),   // 203.0.113.0/24 TEST-NET-3
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),     // 224.0.0.0/4 multicast
            IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)),     // 240.0.0.0/4 reserved
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), // limited broadcast
            IpAddr::V6(Ipv6Addr::LOCALHOST),             // ::1 loopback
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),           // :: unspecified
            IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)), // unique local
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), // link-local
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)), // multicast
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), // documentation
        ];
        for ip in blocked {
            assert!(is_rfc6890_special(ip), "{ip} should be special");
        }

        // Genuinely public/global addresses that must NOT be blocked.
        let allowed = [
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255)),  // just below CGNAT
            IpAddr::V4(Ipv4Addr::new(100, 128, 0, 0)),      // just above CGNAT
            IpAddr::V4(Ipv4Addr::new(192, 1, 2, 3)),        // outside 192.0.0.0/24
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)), // global unicast
        ];
        for ip in allowed {
            assert!(!is_rfc6890_special(ip), "{ip} should NOT be special");
        }
    }
}
