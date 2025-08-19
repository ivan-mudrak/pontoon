mod context;
mod routes;
mod server;

use crate::{context::Context, server::make_server};
use std::str::FromStr;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    let ctx = Context::build().await?;

    let tracing_level = tracing::Level::from_str(&ctx.config.rust_log)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing_level)
            .finish(),
    )
    .map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to initialize tracing subscriber: {}", err),
        )
    })?;

    tracing::info!("Starting auth service with config: {:?}", ctx.config);

    let server = make_server(ctx)?;

    server.await?;

    Ok(())
}
