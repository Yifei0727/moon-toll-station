use auto_server::{Cli, Command, logging};
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install exactly one rustls crypto provider for the whole process. reqwest
    // pulls rustls with the `ring` feature but uses the `-no-provider` variant,
    // so nothing installs a default; quinn/h3 need one. `.ok()` keeps this
    // idempotent if some other dependency installs a provider first.
    let _ = rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let cli = Cli::parse();
    logging::init(cli.config.log_level)?;
    match cli.command {
        Some(Command::Service(svc)) => auto_server::service::run(svc.action),
        None => auto_server::run(cli.config).await,
    }
}
