use std::{net::SocketAddr, time::Duration};

use clap::{Parser, ValueEnum};
use tracing::Level;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "auto-server",
    about = "SOCKS + HTTP CONNECT auto-detect proxy server"
)]
pub struct AppConfig {
    #[arg(long, default_value = "0.0.0.0:1080")]
    pub listen: SocketAddr,

    #[arg(long, help = "Custom DNS server (e.g. 8.8.8.8:53)")]
    pub dns_server: Option<SocketAddr>,

    #[arg(long, default_value_t = 5000)]
    pub handshake_timeout_ms: u64,

    #[arg(long, default_value_t = 10000)]
    pub connect_timeout_ms: u64,

    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,
}

impl AppConfig {
    pub fn from_args() -> Self {
        Self::parse()
    }

    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }
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
