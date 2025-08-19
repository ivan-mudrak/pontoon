use crate::{context::Context, middleware, routes};
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
            .wrap(middleware::auth::Auth)
            .wrap(TracingLogger::default())
            .service(web::resource("/wallet/register").route(web::post().to(routes::register_user)))
            .service(
                web::resource("/wallet/{user_id}/sign").route(web::post().to(routes::sign_message)),
            )
            .service(
                web::resource("/wallet/{user_id}/revoke")
                    .route(web::delete().to(routes::revoke_user)),
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
