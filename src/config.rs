use std::{net::SocketAddr, time::Duration};

use anyhow::bail;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing::Level;

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
        required_if_eq("enable", "h3"),
        help = "PEM private key file for the HTTP/3 (QUIC) listener. Required when --enable h3."
    )]
    pub key: Option<String>,

    #[arg(
        long,
        required_if_eq("enable", "h3"),
        help = "PEM certificate chain (fullchain) file for the HTTP/3 (QUIC) listener. Required when --enable h3."
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
        Ok(())
    }
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
    use clap::Parser;

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
}
