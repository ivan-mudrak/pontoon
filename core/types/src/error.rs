#[derive(Debug, Eq, PartialEq)]
pub struct Error(Box<ErrorKind>);

impl Error {
    pub fn new(kind: ErrorKind) -> Self {
        Error(Box::new(kind))
    }
}

#[non_exhaustive]
#[derive(Debug, Eq, PartialEq)]
pub enum ErrorKind {
    InvalidSignature,
    // 3rd party errors
    Env(crate::env::error::Error),
    Base64(base64::DecodeError),
    AesGcm(aes_gcm::Error),
    Utf8(std::string::FromUtf8Error),
    Rsa(rsa::Error),
    RsaPkcs8(rsa::pkcs8::Error),
    RsaPkcs8Spki(rsa::pkcs8::spki::Error),
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match &*self.0 {
            ErrorKind::InvalidSignature => None,
            ErrorKind::Env(err) => Some(err),
            ErrorKind::Base64(err) => Some(err),
            ErrorKind::AesGcm(err) => Some(err),
            ErrorKind::Utf8(err) => Some(err),
            ErrorKind::Rsa(err) => Some(err),
            ErrorKind::RsaPkcs8(err) => Some(err),
            ErrorKind::RsaPkcs8Spki(err) => Some(err),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &*self.0 {
            ErrorKind::InvalidSignature => write!(f, "{:?}", self.0),
            ErrorKind::Env(err) => write!(f, "Environment error: {}", err),
            ErrorKind::Base64(err) => write!(f, "Base64 error: {}", err),
            ErrorKind::AesGcm(err) => write!(f, "AES-GCM error: {}", err),
            ErrorKind::Utf8(err) => write!(f, "UTF-8 error: {}", err),
            ErrorKind::Rsa(err) => write!(f, "RSA error: {}", err),
            ErrorKind::RsaPkcs8(err) => write!(f, "RSA PKCS8 error: {}", err),
            ErrorKind::RsaPkcs8Spki(err) => write!(f, "RSA PKCS8 SPKI error: {}", err),
        }
    }
}

impl From<crate::env::error::Error> for Error {
    fn from(err: crate::env::error::Error) -> Error {
        Error::new(ErrorKind::Env(err))
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        Error::new(ErrorKind::Base64(err))
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Error {
        Error::new(ErrorKind::Utf8(err))
    }
}

impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Error {
        Error::new(ErrorKind::Rsa(err))
    }
}

impl From<rsa::pkcs8::Error> for Error {
    fn from(err: rsa::pkcs8::Error) -> Error {
        Error::new(ErrorKind::RsaPkcs8(err))
    }
}

impl From<rsa::pkcs8::spki::Error> for Error {
    fn from(err: rsa::pkcs8::spki::Error) -> Error {
        Error::new(ErrorKind::RsaPkcs8Spki(err))
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(err: aes_gcm::Error) -> Error {
        Error::new(ErrorKind::AesGcm(err))
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error::new(kind)
    }
}
