use anyhow::anyhow;
use tracing_subscriber::{EnvFilter, fmt};

use crate::config::LogLevel;

pub fn init(level: LogLevel) -> anyhow::Result<()> {
    let level = tracing::Level::from(level);
    let filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env_lossy();

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(true)
        .try_init()
        .map_err(|err| anyhow!("failed to initialize logging: {err}"))?;

    Ok(())
}
