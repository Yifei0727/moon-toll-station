use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, bail};
use bytes::Bytes;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing::Level;

use crate::capsule;

/// Top-level CLI: optional server configuration flags plus an optional subcommand.
#[derive(Debug, Parser)]
#[command(
    name = "auto-server",
    about = "SOCKS + HTTP CONNECT auto-detect proxy server"
)]
pub struct Cli {
    #[command(flatten)]
    pub config: AppConfig,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage auto-server as a system service (Linux only)
    Service(ServiceCommand),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for Level {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

/// Server runtime configuration.
#[derive(Debug, Clone, Args)]
pub struct AppConfig {
    #[arg(long, default_value = "0.0.0.0:1080")]
    pub listen: SocketAddr,

    #[arg(
        long,
        help = "Custom remote DNS server (e.g. 8.8.8.8:53). If omitted, a built-in remote resolver set is used."
    )]
    pub dns_server: Option<SocketAddr>,

    #[arg(long, default_value_t = 5000)]
    pub handshake_timeout_ms: u64,

    #[arg(long, default_value_t = 10000)]
    pub connect_timeout_ms: u64,

    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    #[arg(
        long,
        help = "Enable automatic upgrade check from GitHub (e.g. 1h, 3d, 1w, 1m)"
    )]
    pub auto_upgrade: Option<String>,

    #[arg(
        long,
        help = "Allow upgrading to pre-release versions (e.g. beta, rc)"
    )]
    pub pre_release: bool,

    #[arg(
        long,
        help = "Prohibit proxying traffic to loopback (127.0.0.0/8) and local (0.0.0.0/8) network addresses. Equivalent to --acl-no-rfc6890."
    )]
    pub no_loopback: bool,

    #[arg(
        long,
        help = "Prohibit proxying traffic to RFC 6890 special-purpose addresses (private, loopback, link-local, CGNAT, multicast, reserved, documentation, etc.). Equivalent to --no-loopback."
    )]
    pub acl_no_rfc6890: bool,

    #[arg(
        long,
        value_enum,
        help = "Enable an additional protocol mode alongside the TCP SOCKS/HTTP proxy. Currently only 'h3' (HTTP/3 MASQUE CONNECT-UDP) is supported. Requires --key, --cert-chain, and --auth-token."
    )]
    pub enable: Option<EnableProtocol>,

    #[arg(
        long,
        help = "PEM private key file for the HTTP/3 (QUIC) listener. Required when --enable h3 unless --acme-ip is set."
    )]
    pub key: Option<String>,

    #[arg(
        long,
        help = "PEM certificate chain (fullchain) file for the HTTP/3 (QUIC) listener. Required when --enable h3 unless --acme-ip is set."
    )]
    pub cert_chain: Option<String>,

    #[arg(
        long,
        required_if_eq("enable", "h3"),
        help = "Shared secret required on every CONNECT-UDP request (Proxy-Authorization). Required when --enable h3, since UDP/443 is a publicly reachable open-proxy port."
    )]
    pub auth_token: Option<String>,

    #[arg(
        long,
        value_name = "IP[,IP...]|auto",
        num_args = 0..=1,
        default_missing_value = "auto",
        help = "Automatically issue and renew a Let's Encrypt short-lived TLS certificate for one or more public IP addresses (RFC 8738, ACME 'shortlived' profile). Pass an explicit public IPv4/IPv6 (comma-separated for dual-stack multi-SAN), or 'auto' (or omit the value) to check local network interfaces first and fall back to ifconfig.io when behind NAT. Uses HTTP-01 (--acme-http-bind) with automatic TLS-ALPN-01 (TCP/443) fallback. Requires --enable h3."
    )]
    pub acme_ip: Option<String>,

    #[arg(
        long,
        value_name = "DIR",
        default_value = "/var/lib/auto-server/acme",
        help = "Directory to persist ACME account key, issued certificate/private key, and metadata when --acme-ip is enabled."
    )]
    pub acme_dir: String,

    #[arg(
        long,
        value_name = "ADDR:PORT",
        default_value = "0.0.0.0:80",
        help = "Local TCP bind address for the temporary ACME HTTP-01 challenge listener during certificate issuance/renewal."
    )]
    pub acme_http_bind: SocketAddr,

    #[arg(
        long,
        value_name = "URL",
        default_value = "https://acme-v02.api.letsencrypt.org/directory",
        help = "ACME v2 directory endpoint URL."
    )]
    pub acme_directory_url: String,

    #[arg(
        long,
        default_value = "0.0.0.0:443",
        help = "HTTP/3 MASQUE (QUIC) listener bind address, independent of --listen. Default 0.0.0.0:443."
    )]
    pub h3_bind: SocketAddr,

    #[arg(
        long,
        default_value = "198.18.0.0/15",
        help = "CIDR pool CONNECT-IP assigns client addresses from (RFC 9484 VPN gateway). One /30 is taken per session for IPv4 pools; one /64 for IPv6. Default 198.18.0.0/15 (RFC 2544 benchmarking range, globally non-routed — suitable as a private VPN pool). Requires root (CAP_NET_ADMIN) at runtime."
    )]
    pub ip_pool: String,

    #[arg(
        long,
        value_name = "IP[,IP...]",
        help = "DNS resolvers to advertise to CONNECT-IP clients in a DNS_ASSIGN capsule (draft-ietf-masque-connect-ip-dns-06 §3.4, an unapproved draft — see docs/QUIC.md). IPv4 and IPv6 accepted; repeatable and/or comma-separated. Each address becomes its own nameserver with increasing SVCB service priority, so the order given IS the preference order. Unset (the default) means no DNS capsule is sent at all, preserving today's behaviour. Requires --enable h3."
    )]
    pub ip_dns: Vec<String>,

    #[arg(
        long,
        value_name = "DOMAIN[,DOMAIN...]",
        help = "DNS search domains (suffix list) advertised alongside --ip-dns (§3.3). Written with or without the root dot; sent as a fully qualified name. Repeatable and/or comma-separated. Ignored, and rejected as pointless, unless --ip-dns is set. Requires --enable h3."
    )]
    pub ip_dns_search: Vec<String>,

    #[arg(
        long,
        value_name = "DOMAIN[,DOMAIN...]",
        help = "Internal domains that the --ip-dns resolvers answer for; each covers its subdomains too (§3.5). Repeatable and/or comma-separated. When --ip-dns is set but this is omitted, the DNS root is advertised, meaning the resolvers answer every name; pass a bare \"\" to say so explicitly. Ignored unless --ip-dns is set. Requires --enable h3."
    )]
    pub ip_dns_internal: Vec<String>,

    #[arg(
        long,
        value_name = "PREFIX/LEN",
        help = "IPv6 NAT64 prefix(es) to advertise in a PREF64 capsule, for IPv6/IPv4 address synthesis (draft-ietf-masque-connect-ip-dns-06 §4.1). Prefix length must be 32, 40, 48, 56, 64 or 96 (RFC 6052 §2.2), e.g. 64:ff9b::/96. Repeatable; order is preserved. Unset means no PREF64 capsule is sent. Requires --enable h3."
    )]
    pub ip_nat64_prefix: Vec<String>,

    #[arg(
        long,
        value_name = "BYTES",
        help = "Cap QUIC datagram size when the path has a smaller MTU (avoids blackholed/fragmented handshakes). Applies to the HTTP/3 (QUIC) listener's transport config: the advertised max UDP payload size, the initial MTU and MTU discovery's upper bound are all clamped to this. Must be >= 1200 (the QUIC minimum)."
    )]
    pub max_mtu: Option<u16>,

    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 60,
        help = "Poll --cert-chain/--key every N seconds and hot-swap the QUIC listener's TLS certificate when the file contents change (symlink-rotation friendly: existing connections keep the old cert). 0 disables polling."
    )]
    pub cert_reload_secs: u64,

    #[arg(
        long,
        value_enum,
        help = "Disable a protocol mode. Currently only 'http', which disables the TCP listener on --listen that serves SOCKS4, SOCKS5 and HTTP CONNECT together (it is NOT an HTTP-only toggle: all three go away). Requires --enable h3, otherwise nothing would be listening."
    )]
    pub disable: Option<DisableProtocol>,
}

/// Protocol modes selectable via `--enable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EnableProtocol {
    /// HTTP/3 MASQUE (RFC 9298 CONNECT-UDP) over QUIC.
    H3,
}

/// Protocol modes selectable via `--disable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DisableProtocol {
    /// The TCP listener on `--listen`: SOCKS4, SOCKS5 and HTTP CONNECT together.
    Http,
}

impl AppConfig {
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    /// Whether destination addresses from the RFC 6890 special-purpose
    /// registry (and the legacy loopback/local subset) must be blocked.
    /// `--no-loopback` and `--acl-no-rfc6890` are equivalent.
    pub fn block_special_addrs(&self) -> bool {
        self.no_loopback || self.acl_no_rfc6890
    }

    /// Whether the TCP listener on `--listen` (SOCKS4 + SOCKS5 + HTTP CONNECT)
    /// should be started. `--disable http` turns it off entirely: the port is
    /// never bound, so only `--enable h3`'s MASQUE listener remains.
    pub fn run_tcp_proxy(&self) -> bool {
        !matches!(self.disable, Some(DisableProtocol::Http))
    }

    /// Cross-flag constraints that clap cannot express. Called before anything
    /// is bound so a configuration that would leave the process serving nothing
    /// fails fast with an actionable message.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.run_tcp_proxy() && !matches!(self.enable, Some(EnableProtocol::H3)) {
            bail!("--disable http requires --enable h3: nothing would be listening");
        }
        if matches!(self.enable, Some(EnableProtocol::H3)) {
            if self.auth_token.is_none() {
                bail!("--enable h3 requires --auth-token");
            }
            if self.acme_ip.is_none() {
                if self.key.is_none() || self.cert_chain.is_none() {
                    bail!("--enable h3 requires --key and --cert-chain (or --acme-ip)");
                }
            } else if self.key.is_some() != self.cert_chain.is_some() {
                bail!("--key and --cert-chain must be specified together");
            }
        } else if self.acme_ip.is_some() {
            bail!("--acme-ip requires --enable h3");
        }
        if let Some(raw) = &self.acme_ip {
            let trimmed = raw.trim();
            if !trimmed.eq_ignore_ascii_case("auto") {
                let mut count = 0usize;
                for part in trimmed.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    count += 1;
                    let ip: IpAddr = part.parse().with_context(|| {
                        format!(
                            "--acme-ip: {part:?} is not a valid IPv4/IPv6 address or 'auto'"
                        )
                    })?;
                    if self
                        .acme_directory_url
                        .to_ascii_lowercase()
                        .contains("letsencrypt.org")
                        && crate::server::is_rfc6890_special(ip)
                    {
                        bail!(
                            "--acme-ip: {ip} is a special-purpose/private/loopback (RFC 6890) address; \
                             Let's Encrypt only issues certificates for publicly routable IP addresses"
                        );
                    }
                }
                if count == 0 {
                    bail!("--acme-ip: expected one or more IP addresses or 'auto'");
                }
            }
        }
        if let Some(mtu) = self.max_mtu
            && mtu < 1200
        {
            bail!(
                "--max-mtu {mtu} is below the QUIC minimum of 1200 bytes; \
                 smaller values cannot carry the initial handshake packets"
            );
        }
        Ok(())
    }

    /// True when any CONNECT-IP DNS or NAT64 option was configured, i.e. the
    /// request stream will carry something beyond RFC 9484's own capsules.
    pub fn has_connect_ip_dns(&self) -> bool {
        !self.ip_dns.is_empty() || !self.ip_nat64_prefix.is_empty()
    }

    /// Encode the CONNECT-IP `DNS_ASSIGN` / `PREF64` signalling capsules from
    /// the `--ip-dns*` and `--ip-nat64-prefix` flags
    /// (`draft-ietf-masque-connect-ip-dns-06`).
    ///
    /// Called once at `--enable h3` startup, so a bad combination fails there
    /// rather than per-session — the same contract `--ip-pool` has. Everything
    /// is validated *here* rather than in `capsule.rs`, because this is where an
    /// actionable operator-facing message can be produced.
    pub fn connect_ip_capsules(&self) -> anyhow::Result<capsule::ConnectIpCapsules> {
        Ok(capsule::ConnectIpCapsules {
            dns_assign: self.build_dns_assign()?,
            pref64: self.build_pref64()?,
        })
    }

    fn build_dns_assign(&self) -> anyhow::Result<Option<Bytes>> {
        // One nameserver per address, priorities ascending in the order given:
        // §3.2 requires ServiceMode (RFC 9460 §2.4.3), where alternatives are
        // separate records ranked by priority and 0 is forbidden.
        let mut nameservers = Vec::new();
        for raw in split_flag_values(&self.ip_dns) {
            let addr: IpAddr = raw
                .parse()
                .with_context(|| format!("--ip-dns: {raw:?} is not an IPv4 or IPv6 address"))?;
            if nameservers.len() >= u16::MAX as usize {
                bail!("--ip-dns: too many resolvers; SVCB service priority is a 16-bit field");
            }
            let (mut ipv4, mut ipv6) = (Vec::new(), Vec::new());
            match addr {
                IpAddr::V4(a) => ipv4.push(a),
                IpAddr::V6(a) => ipv6.push(a),
            }
            nameservers.push(capsule::DnsNameserver {
                service_priority: nameservers.len() as u16 + 1,
                ipv4,
                ipv6,
                // No encrypted transport: unencrypted DNS over port 53 only, so
                // §3.2 forbids an authentication domain and any alpn parameters.
                auth_domain: String::new(),
                service_parameters: Bytes::new(),
            });
        }

        if nameservers.is_empty() {
            if !self.ip_dns_search.is_empty() || !self.ip_dns_internal.is_empty() {
                bail!(
                    "--ip-dns-search/--ip-dns-internal are meaningless without at least one \
                     --ip-dns resolver"
                );
            }
            return Ok(None);
        }

        // §3.5: no qualification means the resolvers answer every name, which is
        // expressed by advertising the DNS root.
        let mut internal_domains = split_flag_values(&self.ip_dns_internal)
            .map(|d| normalize_domain(d, true))
            .collect::<anyhow::Result<Vec<_>>>()?;
        if internal_domains.is_empty() {
            internal_domains.push(String::new());
        }
        let search_domains = split_flag_values(&self.ip_dns_search)
            .map(|d| normalize_domain(d, false))
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Some(capsule::encode_dns_assign(&[
            capsule::DnsConfiguration {
                nameservers,
                internal_domains,
                search_domains,
            },
        ])))
    }

    fn build_pref64(&self) -> anyhow::Result<Option<Bytes>> {
        let prefixes = split_flag_values(&self.ip_nat64_prefix)
            .map(parse_nat64_prefix)
            .collect::<anyhow::Result<Vec<_>>>()?;
        if prefixes.is_empty() {
            return Ok(None);
        }
        Ok(Some(capsule::encode_pref64(&prefixes)))
    }
}

/// Expand a repeatable flag that additionally accepts comma-separated values:
/// `--ip-dns 8.8.8.8 --ip-dns 1.1.1.1` and `--ip-dns 8.8.8.8,1.1.1.1` are equal.
fn split_flag_values(values: &[String]) -> impl Iterator<Item = &str> {
    values
        .iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Canonicalise operator input into a DNS presentation-format name. §3.1 asks
/// for a Fully Qualified Domain Name in IDNA A-label form, so we always emit the
/// terminating root dot (which is also what `connect-ip-go` demands of its own
/// inputs) whether or not the operator wrote it.
///
/// `allow_root` distinguishes the two places a name may legitimately be empty:
/// an empty internal domain is the DNS root and means "resolves everything"
/// (§3.5), whereas an empty search domain has no meaning.
fn normalize_domain(raw: &str, allow_root: bool) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "." {
        return if allow_root {
            Ok(String::new())
        } else {
            bail!("{raw:?} is not a usable search domain; give a domain name");
        };
    }
    let body = trimmed.strip_suffix('.').unwrap_or(trimmed);
    for label in body.split('.') {
        if label.is_empty() {
            bail!("{raw:?} has an empty label (leading, trailing or doubled dot)");
        }
        if label.len() > 63 {
            bail!("{raw:?} has a label longer than the 63-octet DNS limit");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            bail!("{raw:?} must be an IDNA A-label: lower-case ASCII letters, digits and '-'");
        }
    }
    let fqdn = format!("{body}.");
    if fqdn.len() > 255 {
        bail!("{raw:?} exceeds the 255-octet limit of RFC 1035 §2.3.4");
    }
    Ok(fqdn)
}

/// `<IPv6-prefix>/<length>` -> a PREF64 `NAT64 Prefix`.
fn parse_nat64_prefix(raw: &str) -> anyhow::Result<capsule::Nat64Prefix> {
    let (addr, len) = raw.split_once('/').with_context(|| {
        format!("--ip-nat64-prefix: {raw:?} must be <IPv6-prefix>/<length>, e.g. 64:ff9b::/96")
    })?;
    let addr: Ipv6Addr = addr
        .trim()
        .parse()
        .with_context(|| format!("--ip-nat64-prefix: {addr:?} is not an IPv6 address"))?;
    let len: u8 = len
        .trim()
        .parse()
        .with_context(|| format!("--ip-nat64-prefix: {len:?} is not a prefix length"))?;
    if !capsule::NAT64_PREFIX_LENGTHS.contains(&len) {
        bail!(
            "--ip-nat64-prefix: /{len} is not a permitted NAT64 prefix length; \
             must be one of {:?} (RFC 6052 §2.2)",
            capsule::NAT64_PREFIX_LENGTHS
        );
    }
    // Reject non-canonical input ("64:ff9b::1/96"): the synthetic IPv4 space is
    // determined by the prefix alone, so stray bits would silently mislead.
    let mask = u128::MAX << (128 - len);
    if u128::from(addr) & !mask != 0 {
        bail!(
            "--ip-nat64-prefix: {addr}/{len} has bits set below the prefix length; \
             give the network address (e.g. {}/{len})",
            Ipv6Addr::from(u128::from(addr) & mask)
        );
    }
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&addr.octets()[..12]);
    Ok(capsule::Nat64Prefix { prefix_len: len, prefix })
}

#[derive(Debug, Clone, Args)]
pub struct ServiceCommand {
    #[command(subcommand)]
    pub action: ServiceAction,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ServiceAction {
    /// Install auto-server as a system service (writes the unit/init script)
    ///
    /// Any extra arguments after `--` are forwarded to the auto-server binary,
    /// e.g. `auto-server service install --bin-path /usr/local/bin/auto-server -- --listen 0.0.0.0:9999 --acl-no-rfc6890`.
    Install {
        /// Copy the running binary to this path and reference it in ExecStart /
        /// DAEMON (e.g. /usr/local/bin/auto-server). If omitted, the running
        /// binary's own (resolved) path is used.
        #[arg(long = "bin-path")]
        bin_path: Option<String>,

        /// Extra arguments forwarded to the auto-server binary (pass after `--`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<String>,
    },
    /// Enable the service to start automatically at boot
    Enable,
    /// Start the service through the system service manager
    Start,
    /// Stop the service through the system service manager
    Stop,
    /// Remove the service and clean up all files
    Uninstall,
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, Cli, DisableProtocol};
    use crate::capsule;
    use clap::Parser;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn config_from(args: &[&str]) -> AppConfig {
        let mut argv = vec!["auto-server"];
        argv.extend_from_slice(args);
        Cli::parse_from(argv).config
    }

    /// Minimal arguments that satisfy `--enable h3`'s clap requirements.
    const H3_ARGS: &[&str] = &[
        "--enable",
        "h3",
        "--key",
        "key.pem",
        "--cert-chain",
        "cert.pem",
        "--auth-token",
        "s3cr3t",
    ];

    #[test]
    fn parses_disable_http() {
        assert_eq!(config_from(&[]).disable, None);
        assert_eq!(
            config_from(&["--disable", "http"]).disable,
            Some(DisableProtocol::Http)
        );
    }

    #[test]
    fn tcp_proxy_runs_unless_disabled() {
        assert!(config_from(&[]).run_tcp_proxy());
        assert!(config_from(H3_ARGS).run_tcp_proxy());
        assert!(!config_from(&["--disable", "http"]).run_tcp_proxy());
    }

    #[test]
    fn validate_rejects_disable_http_without_enable_h3() {
        let err = config_from(&["--disable", "http"])
            .validate()
            .expect_err("disable http without enable h3 must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("--enable h3"),
            "error should point at --enable h3, got: {message}"
        );
    }

    #[test]
    fn validate_accepts_disable_http_with_enable_h3() {
        let mut args = H3_ARGS.to_vec();
        args.extend_from_slice(&["--disable", "http"]);
        config_from(&args)
            .validate()
            .expect("disable http + enable h3 is valid");
    }

    #[test]
    fn validate_accepts_configs_that_listen_on_something() {
        config_from(&[])
            .validate()
            .expect("default config is valid");
        config_from(H3_ARGS).validate().expect("enable h3 is valid");
    }

    #[test]
    fn max_mtu_below_quic_minimum_is_rejected() {
        let mut args = H3_ARGS.to_vec();
        args.extend_from_slice(&["--max-mtu", "1199"]);
        let err = config_from(&args)
            .validate()
            .expect_err("1199 is below the QUIC minimum and must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("1200"),
            "error should mention the 1200-byte QUIC minimum, got: {message}"
        );
    }

    #[test]
    fn max_mtu_at_quic_minimum_is_accepted() {
        let mut args = H3_ARGS.to_vec();
        args.extend_from_slice(&["--max-mtu", "1200"]);
        config_from(&args)
            .validate()
            .expect("1200 is the QUIC minimum and must be accepted");
    }

    // -- CONNECT-IP DNS / PREF64 (draft-ietf-masque-connect-ip-dns-06) ----

    fn dns_capsule(args: &[&str]) -> Vec<capsule::DnsConfiguration> {
        let bytes = config_from(args)
            .connect_ip_capsules()
            .expect("dns flags must be valid")
            .dns_assign
            .expect("expected a DNS_ASSIGN capsule");
        capsule::decode_dns_assign(&bytes).expect("must decode what we encode")
    }

    #[test]
    fn no_dns_flags_sends_no_dns_capsule() {
        for args in [&[][..], H3_ARGS] {
            let built = config_from(args)
                .connect_ip_capsules()
                .expect("default config is valid");
            assert!(built.dns_assign.is_none(), "no DNS_ASSIGN by default");
            assert!(built.pref64.is_none(), "no PREF64 by default");
            assert!(built.is_empty());
            assert!(!config_from(args).has_connect_ip_dns());
        }
    }

    #[test]
    fn ip_dns_accepts_repeatable_and_comma_separated_lists() {
        // Both spellings must produce the same nameservers, ranked in the order
        // the operator gave them (§3.2 ServiceMode forbids priority 0).
        let repeated = dns_capsule(&["--ip-dns", "8.8.8.8", "--ip-dns", "2001:db8::1"]);
        let comma = dns_capsule(&["--ip-dns", "8.8.8.8,2001:db8::1"]);
        assert_eq!(repeated, comma);

        let ns = &repeated[0].nameservers;
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0].service_priority, 1);
        assert_eq!(ns[0].ipv4, vec![Ipv4Addr::new(8, 8, 8, 8)]);
        assert!(ns[0].ipv6.is_empty());
        assert_eq!(ns[1].service_priority, 2);
        assert_eq!(ns[1].ipv6, vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)]);

        // Unencrypted DNS only -> no authentication domain, no SvcParams (§3.2).
        assert!(ns[0].auth_domain.is_empty());
        assert!(ns[0].service_parameters.is_empty());
    }

    #[test]
    fn ip_dns_defaults_internal_domains_to_the_dns_root() {
        // §3.5: an empty internal domain is the DNS root, i.e. these resolvers
        // answer every name — the only sensible reading of an unqualified
        // `--ip-dns`.
        assert_eq!(dns_capsule(&["--ip-dns", "8.8.8.8"])[0].internal_domains, vec![""]);

        // Explicit root and a real split-horizon domain both survive round-trip.
        assert_eq!(
            dns_capsule(&["--ip-dns", "8.8.8.8", "--ip-dns-internal", "."])[0].internal_domains,
            vec![""]
        );
        assert_eq!(
            dns_capsule(&[
                "--ip-dns",
                "8.8.8.8",
                "--ip-dns-internal",
                "internal.corp.example"
            ])[0]
                .internal_domains,
            vec!["internal.corp.example."]
        );
    }

    #[test]
    fn domains_are_sent_as_dot_terminated_fqdns() {
        let cfg = dns_capsule(&[
            "--ip-dns",
            "8.8.8.8",
            "--ip-dns-search",
            "corp.example,example.net.",
        ]);
        assert_eq!(cfg[0].search_domains, vec!["corp.example.", "example.net."]);
    }

    #[test]
    fn malformed_dns_flags_are_rejected_at_build_time() {
        for (args, needle) in [
            (vec!["--ip-dns", "not-an-ip"], "--ip-dns"),
            (
                vec!["--ip-dns", "8.8.8.8", "--ip-dns-search", "corp..example"],
                "empty label",
            ),
            (
                vec!["--ip-dns", "8.8.8.8", "--ip-dns-search", "Corp.Example"],
                "A-label",
            ),
        ] {
            let mut full = H3_ARGS.to_vec();
            full.extend_from_slice(&args);
            let err = config_from(&full)
                .connect_ip_capsules()
                .expect_err("invalid dns flags must be rejected");
            assert!(
                err.to_string().contains(needle),
                "expected {needle:?} in: {err}"
            );
        }
    }

    #[test]
    fn domain_flags_without_a_resolver_are_rejected() {
        let err = config_from(&["--ip-dns-search", "corp.example"])
            .connect_ip_capsules()
            .expect_err("search domains without a resolver are pointless");
        assert!(err.to_string().contains("--ip-dns"), "got: {err}");
    }

    #[test]
    fn nat64_prefix_flags_round_trip() {
        let built = config_from(&[
            "--ip-nat64-prefix",
            "64:ff9b::/96",
            "--ip-nat64-prefix",
            "2001:db8:64::/48",
        ])
        .connect_ip_capsules()
        .expect("valid NAT64 prefixes");
        let bytes = built.pref64.expect("expected a PREF64 capsule");
        let prefixes = capsule::decode_pref64(&bytes).expect("must decode what we encode");

        assert_eq!(prefixes.len(), 2);
        let mut well_known = [0u8; 12];
        well_known[..4].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b]);
        assert_eq!(prefixes[0].prefix_len, 96);
        assert_eq!(prefixes[0].prefix, well_known);
        let mut local = [0u8; 12];
        local[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x64]);
        assert_eq!(prefixes[1].prefix_len, 48);
        assert_eq!(prefixes[1].prefix, local);
    }

    #[test]
    fn malformed_nat64_prefixes_are_rejected() {
        for (arg, needle) in [
            ("64:ff9b::", "must be"),
            ("64:ff9b::/95", "prefix length"),
            ("64:ff9b::/97", "prefix length"),
            ("64:ff9b::/128", "prefix length"),
            ("64:ff9b::1/96", "below the prefix length"),
            ("8.8.8.8/32", "IPv6 address"),
        ] {
            let mut full = H3_ARGS.to_vec();
            full.extend_from_slice(&["--ip-nat64-prefix", arg]);
            let err = config_from(&full)
                .connect_ip_capsules()
                .expect_err("{arg} must be rejected");
            assert!(err.to_string().contains(needle), "{arg} -> {err}");
        }
    }

    #[test]
    fn too_long_domain_is_rejected() {
        let long = format!("{}.example", "a".repeat(64));
        let mut full = H3_ARGS.to_vec();
        full.extend_from_slice(&["--ip-dns", "8.8.8.8", "--ip-dns-search", &long]);
        let err = config_from(&full)
            .connect_ip_capsules()
            .expect_err("over-long label must be rejected");
        assert!(err.to_string().contains("63-octet"), "got: {err}");
    }

    // -- ACME public IP issuance flags ----------------------------------------

    #[test]
    fn acme_ip_explicit_and_auto_are_valid() {
        let explicit = config_from(&[
            "--enable",
            "h3",
            "--auth-token",
            "s3cr3t",
            "--acme-ip",
            "203.0.113.10",
            "--acme-directory-url",
            "https://mock.acme.test/directory",
        ]);
        assert_eq!(explicit.acme_ip.as_deref(), Some("203.0.113.10"));
        explicit.validate().expect("explicit IP with non-LE dir is valid");

        let public_le = config_from(&[
            "--enable",
            "h3",
            "--auth-token",
            "s3cr3t",
            "--acme-ip",
            "1.1.1.1",
        ]);
        public_le.validate().expect("public IP with LE dir is valid");

        let auto_explicit = config_from(&[
            "--enable",
            "h3",
            "--auth-token",
            "s3cr3t",
            "--acme-ip",
            "auto",
        ]);
        assert_eq!(auto_explicit.acme_ip.as_deref(), Some("auto"));
        auto_explicit.validate().expect("auto mode is valid");

        let bare = config_from(&[
            "--enable",
            "h3",
            "--auth-token",
            "s3cr3t",
            "--acme-ip",
            "--h3-bind",
            "0.0.0.0:8443",
        ]);
        assert_eq!(bare.acme_ip.as_deref(), Some("auto"));
        assert_eq!(bare.h3_bind.port(), 8443);
        bare.validate().expect("bare --acme-ip defaults to auto");

        let dual_stack = config_from(&[
            "--enable",
            "h3",
            "--auth-token",
            "s3cr3t",
            "--acme-ip",
            "1.1.1.1,2606:4700:4700::1111",
        ]);
        dual_stack.validate().expect("comma-separated dual-stack IPv4+IPv6 is valid");
    }

    #[test]
    fn acme_ip_validation_rejects_invalid_combinations() {
        let no_h3 = config_from(&["--acme-ip", "1.1.1.1"])
            .validate()
            .expect_err("--acme-ip without --enable h3 must fail");
        assert!(no_h3.to_string().contains("--enable h3"));

        let h3_no_creds = config_from(&["--enable", "h3", "--auth-token", "s3cr3t"])
            .validate()
            .expect_err("--enable h3 without key/cert or acme-ip must fail");
        assert!(h3_no_creds.to_string().contains("--acme-ip"));

        let half_manual = config_from(&[
            "--enable",
            "h3",
            "--auth-token",
            "s3cr3t",
            "--acme-ip",
            "1.1.1.1",
            "--key",
            "key.pem",
        ])
        .validate()
        .expect_err("half manual key/cert must fail");
        assert!(half_manual.to_string().contains("together"));

        let bad_ip = config_from(&[
            "--enable",
            "h3",
            "--auth-token",
            "s3cr3t",
            "--acme-ip",
            "example.com",
        ])
        .validate()
        .expect_err("domain name for --acme-ip must fail");
        assert!(bad_ip.to_string().contains("--acme-ip"));

        let private_le = config_from(&[
            "--enable",
            "h3",
            "--auth-token",
            "s3cr3t",
            "--acme-ip",
            "127.0.0.1",
        ])
        .validate()
        .expect_err("RFC 6890 IP against letsencrypt.org must fail");
        assert!(private_le.to_string().contains("RFC 6890"));
    }
}
