use crate::context::Context;
use actix_http::h1;
use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Payload, Service, ServiceRequest, ServiceResponse, Transform},
    web::{Bytes, Data},
    Error, HttpResponse,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use repositories::wallet::WalletRepository;
use std::rc::Rc;
use types::{api_key::ApiKey, secret::mask::Masked};
use uuid::Uuid;

pub struct Auth;

impl<S, B> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct AuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();

        Box::pin(async move {
            if let Some(context) = req.app_data::<Data<Context>>() {
                let ctx = context.clone();
                match AuthData::from_request(&mut req).await {
                    Ok(auth_data) => {
                        tracing::debug!("Extracted authentication data: {:?}", auth_data);

                        match auth_data.check_authentication(&ctx).await {
                            Ok(_) => {
                                return svc.call(req).await.map(|res| res.map_into_left_body())
                            }
                            Err(err) => {
                                tracing::error!("Authentication failed: {}", err);
                                return Ok(req
                                    .into_response(
                                        HttpResponse::Unauthorized().body("Unauthorized"),
                                    )
                                    .map_into_right_body());
                            }
                        }
                    }
                    Err(err) => {
                        tracing::error!(
                            "Failed to extract authentication message from request: {}",
                            err
                        );
                        return Ok(req
                            .into_response(HttpResponse::Unauthorized().body("Unauthorized"))
                            .map_into_right_body());
                    }
                }
            } else {
                tracing::error!("Failed to extract context");
                return Ok(req
                    .into_response(HttpResponse::InternalServerError().body("No context found"))
                    .map_into_right_body());
            }
        })
    }
}

#[derive(Debug)]
pub struct AuthData {
    pub api_key: Masked<ApiKey>,
    pub signature: String,
    pub timestamp: u64,
    pub http_method: String,
    pub request_path: String,
    pub request_query: String,
    pub request_body: Option<String>,
}

impl AuthData {
    pub async fn from_request(req: &mut ServiceRequest) -> anyhow::Result<Self> {
        let timestamp = req
            .headers()
            .get("x-timestamp")
            .and_then(|value| value.to_str().ok())
            .and_then(|str| str.parse::<u64>().ok())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid x-timestamp header"))?;
        let api_key = req
            .headers()
            .get("x-api-key")
            .and_then(|value| value.to_str().ok())
            .and_then(|str| Uuid::parse_str(str).ok())
            .map(ApiKey::from)
            .map(Masked::from)
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid x-api-key header"))?;
        let signature = req
            .headers()
            .get("x-signature")
            .and_then(|value| value.to_str().map(|s| s.to_string()).ok())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid x-signature header"))?;
        let http_method = req.method().to_string();
        let request_path = req.path().to_string();
        let request_query = req.query_string().to_string();
        let request_bytes = req
            .extract::<Bytes>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to extract request body as bytes"))?;
        let request_body = String::from_utf8(request_bytes.to_vec()).ok();

        req.set_payload(bytes_to_payload(request_bytes));

        Ok(AuthData {
            api_key,
            signature,
            timestamp,
            http_method,
            request_path,
            request_query,
            request_body,
        })
    }

    pub async fn check_authentication(&self, ctx: &Context) -> anyhow::Result<()> {
        let encrypted_credentials = WalletRepository::get_credentials(&ctx.database, &self.api_key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid API key"))?;

        let credentials = encrypted_credentials.decrypt(&ctx.config.master_key)?;

        // Create the message to sign
        let message = format!(
            "{}{}{}{}{}",
            self.timestamp,
            self.http_method,
            self.request_path,
            self.request_query,
            self.request_body.as_ref().unwrap_or(&String::new())
        );

        credentials.check_authentication(&message, &self.signature)?;

        Ok(())
    }
}

fn bytes_to_payload(buf: Bytes) -> Payload {
    let (_, mut pl) = h1::Payload::create(true);
    pl.unread_data(buf);
    Payload::from(pl)
}
