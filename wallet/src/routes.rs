use crate::context::Context;
use actix_web::{
    web::{Data, Json, Path},
    HttpRequest, HttpResponse,
};
use repositories::wallet::WalletRepository;
use serde::Serialize;
use types::{
    client::ApiKey,
    redact::Masked,
    user::{User, UserId},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct RegisterUserResponse {
    pub user_id: UserId,
    pub pub_key: String,
}

pub(crate) async fn register_user(
    ctx: Data<Context>,
    req: HttpRequest,
) -> actix_web::Result<HttpResponse> {
    tracing::debug!("Registering new user");

    let api_key = req
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .and_then(|str| Uuid::parse_str(str).ok())
        .map(ApiKey::from)
        .map(Masked::from)
        .ok_or_else(|| {
            actix_web::error::ErrorUnauthorized("Missing or invalid x-api-key header")
        })?;

    let user = User::new()
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create user"))?;

    let response = RegisterUserResponse {
        user_id: user.id().clone(),
        pub_key: user.signing_key.public_key_pem().map_err(|_| {
            actix_web::error::ErrorInternalServerError("Failed to get public key PEM")
        })?,
    };

    let encrypted_user = user.encrypt(&ctx.config.master_key).map_err(|err| {
        tracing::error!("Failed to encrypt user: {}", err);
        actix_web::error::ErrorInternalServerError("Failed to encrypt user")
    })?;

    match WalletRepository::register_user(&ctx.database, api_key, encrypted_user).await {
        Ok(_) => Ok(HttpResponse::Created().json(response)),
        Err(err) => {
            tracing::error!("Failed to register user: {}", err);
            Err(actix_web::error::ErrorInternalServerError(
                "Failed to register user",
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SignMessageResponse {
    pub message: String,
    pub signature: String,
}

pub(crate) async fn sign_message(
    ctx: Data<Context>,
    path: Path<UserId>,
    body: Json<String>,
) -> actix_web::Result<HttpResponse> {
    let user_id = path.into_inner();
    let message = body.into_inner();
    tracing::debug!("Signing message on behalf of user: {:?}", user_id);

    // Get user
    let encrypted_user = WalletRepository::get_user(&ctx.database, user_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to get user: {}", err);
            actix_web::error::ErrorInternalServerError("Failed to get user")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("User not found"))?;

    // Decrypt private key
    let user = encrypted_user
        .decrypt(&ctx.config.master_key)
        .map_err(|err| {
            tracing::error!("Failed to decrypt user: {}", err);
            actix_web::error::ErrorInternalServerError("Failed to decrypt user")
        })?;

    // Sign message
    let signature = user.signing_key.sign_message(message.as_str());

    Ok(HttpResponse::Ok().json(SignMessageResponse { message, signature }))
}

pub(crate) async fn revoke_user(
    ctx: Data<Context>,
    path: Path<UserId>,
) -> actix_web::Result<HttpResponse> {
    let user_id = path.into_inner();
    tracing::debug!("Revoking user: {:?}", user_id);

    match WalletRepository::delete_user(&ctx.database, user_id.clone()).await {
        Ok(_) => {
            tracing::debug!("User {:?} revoked successfully", user_id);
            Ok(HttpResponse::NoContent().finish())
        }
        Err(err) => {
            tracing::error!("Failed to revoke user: {}", err);
            Err(actix_web::error::ErrorInternalServerError(
                "Failed to revoke user",
            ))
        }
    }
}
