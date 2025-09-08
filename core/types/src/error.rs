use http::StatusCode;
use thiserror::Error;

#[non_exhaustive]
#[derive(Debug, Error, Eq, PartialEq)]
pub enum Error {
    // === Domain errors ===
    #[error("invalid signature")]
    InvalidSignature,

    // === Third-party / infrastructure ===
    #[error(transparent)]
    Env(#[from] crate::env::error::Error),

    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    #[error(transparent)]
    AesGcm(#[from] aes_gcm::Error),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Rsa(#[from] rsa::Error),

    #[error(transparent)]
    RsaPkcs8(#[from] rsa::pkcs8::Error),

    #[error(transparent)]
    RsaPkcs8Spki(#[from] rsa::pkcs8::spki::Error),
}

impl Error {
    #[inline]
    pub fn code(&self) -> &'static str {
        match &self {
            Error::InvalidSignature => "ERR_SIG_MALFORMED",
            Error::Env(_) => "ERR_ENV",
            Error::Base64(_) => "ERR_BASE64",
            Error::AesGcm(_) => "ERR_AES_GCM",
            Error::Utf8(_) => "ERR_UTF8",
            Error::Rsa(_) => "ERR_RSA",
            Error::RsaPkcs8(_) => "ERR_RSA_PKCS8",
            Error::RsaPkcs8Spki(_) => "ERR_RSA_PKCS8_SPKI",
        }
    }

    #[inline]
    pub fn http_status(&self) -> StatusCode {
        match &self {
            Error::InvalidSignature => StatusCode::BAD_REQUEST,
            Error::Base64(_)
            | Error::AesGcm(_)
            | Error::Utf8(_)
            | Error::Rsa(_)
            | Error::RsaPkcs8(_)
            | Error::RsaPkcs8Spki(_)
            | Error::Env(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
