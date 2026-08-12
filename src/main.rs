use auto_server::{Cli, Command, logging};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    logging::init(cli.config.log_level)?;
    match cli.command {
        Some(Command::Service(svc)) => auto_server::service::run(svc.action),
        None => auto_server::run(cli.config).await,
    }
}
