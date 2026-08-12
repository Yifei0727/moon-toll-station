use std::{net::SocketAddr, time::Duration};

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
    /// e.g. `auto-server service install -- --listen 0.0.0.0:9999 --acl-no-rfc6890`.
    Install {
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
