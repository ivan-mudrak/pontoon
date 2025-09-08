use crate::context::Context;
use actix_web::{
    web::{Data, Json, Query},
    HttpResponse,
};
use repositories::client::ClientRepository;
use serde::{Deserialize, Serialize};
use types::{api_key::ApiKey, client::Client, secret::mask::Masked};

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
}

pub(crate) async fn create_client(
    ctx: Data<Context>,
    body: Json<CreateClientRequest>,
) -> actix_web::Result<HttpResponse> {
    tracing::debug!("Creating client: {:?}", body);
    let client = Client::new(body.name.clone());
    match client.encrypt(&ctx.config.master_key) {
        Ok(encrypted_client) => {
            match ClientRepository::create(&ctx.database, encrypted_client).await {
                Ok(_) => Ok(HttpResponse::Created().json(client)),
                Err(err) => {
                    tracing::error!("Failed to store client: {}", err);
                    Ok(HttpResponse::InternalServerError().finish())
                }
            }
        }
        Err(err) => {
            tracing::error!("Failed to encrypt client: {}", err);
            return Ok(HttpResponse::InternalServerError().finish());
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ClientQuery {
    name: String,
}

#[derive(Debug, Serialize)]
pub struct GetClientResponse {
    pub name: String,
    pub api_key: Masked<ApiKey>,
}

pub(crate) async fn get_client(
    ctx: Data<Context>,
    query: Query<ClientQuery>,
) -> actix_web::Result<HttpResponse> {
    match ClientRepository::find_by_name(&ctx.database, &query.name).await {
        Ok(Some(client)) => {
            tracing::debug!("Retrieved client: {:?}", client);
            let response = GetClientResponse {
                name: client.name,
                api_key: client.credentials.api_key,
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Ok(None) => {
            tracing::debug!("Client not found");
            Ok(HttpResponse::NotFound().finish())
        }
        Err(err) => {
            tracing::error!("Failed to retrieve client: {}", err);
            Ok(HttpResponse::InternalServerError().finish())
        }
    }
}
