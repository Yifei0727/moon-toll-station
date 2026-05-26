use auto_server::{AppConfig, logging};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AppConfig::from_args();
    logging::init(config.log_level)?;
    auto_server::run(config).await
}
