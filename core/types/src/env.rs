use error::{Error, ErrorKind};
use std::io::Read;
use std::str::FromStr;
use std::{fmt::Display, fs::File};

pub fn read_from_env_file<T>(env_var_name: &str) -> Result<T, Error>
where
    T: FromStr,
    T::Err: Display,
{
    let content = read_env_file(env_var_name)?;

    let secret = content
        .parse()
        .map_err(|err| ErrorKind::ParseFailure(format!("{}", err).into()))?;

    Ok(secret)
}

pub fn read_env_file(env_var_name: &str) -> Result<String, Error> {
    let file_path = std::env::var(env_var_name)?;

    read_file(&file_path)
}

pub fn read_file(file_path: &str) -> Result<String, Error> {
    let mut file = File::open(file_path)?;

    let mut content = String::new();
    file.read_to_string(&mut content)?;

    Ok(content)
}

pub mod error {

    #[derive(Debug, Eq, PartialEq)]
    pub struct Error(Box<ErrorKind>);

    impl Error {
        pub fn new(kind: ErrorKind) -> Self {
            Error(Box::new(kind))
        }
    }

    #[non_exhaustive]
    #[derive(Debug)]
    pub enum ErrorKind {
        ParseFailure(String),
        // 3rd party errors
        Io(std::io::Error),
        Var(std::env::VarError),
    }

    impl std::error::Error for Error {
        fn cause(&self) -> Option<&dyn std::error::Error> {
            match &*self.0 {
                ErrorKind::ParseFailure(_) => None,
                ErrorKind::Io(err) => Some(err),
                ErrorKind::Var(err) => Some(err),
            }
        }
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match &*self.0 {
                ErrorKind::ParseFailure(msg) => write!(f, "Parse failure: {}", msg),
                ErrorKind::Io(err) => write!(f, "IO error: {}", err),
                ErrorKind::Var(err) => write!(f, "Environment variable error: {}", err),
            }
        }
    }

    impl PartialEq for ErrorKind {
        fn eq(&self, other: &Self) -> bool {
            format!("{:?}", self) == format!("{:?}", other)
        }
    }

    impl Eq for ErrorKind {}

    impl From<std::io::Error> for Error {
        fn from(err: std::io::Error) -> Error {
            Error::new(ErrorKind::Io(err))
        }
    }

    impl From<std::env::VarError> for Error {
        fn from(err: std::env::VarError) -> Error {
            Error::new(ErrorKind::Var(err))
        }
    }

    impl From<ErrorKind> for Error {
        fn from(kind: ErrorKind) -> Error {
            Error::new(kind)
        }
    }
}
