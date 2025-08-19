use crate::{context::Context, routes};
use actix_web::{
    dev::Server,
    web::{self, Data},
    App, HttpResponse, HttpServer,
};
use std::net::Ipv4Addr;
use tracing_actix_web::TracingLogger;

pub fn make_server(ctx: Context) -> anyhow::Result<Server> {
    let port = ctx.config.port;
    let data = Data::new(ctx);

    let server = HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            // TODO: add authentication middleware
            .wrap(TracingLogger::default())
            .service(
                web::resource("/admin/client")
                    .route(web::get().to(routes::get_client))
                    .route(web::post().to(routes::create_client)),
            )
            .default_service(web::to(|| {
                tracing::error!("Route not found");
                HttpResponse::NotFound()
            }))
    })
    .bind((Ipv4Addr::UNSPECIFIED, port))?
    .run();

    Ok(server)
}
