use secrecy::SecretString;

pub trait DatabaseConnection {
    fn connection_string(&self) -> SecretString;
}

pub mod postgres {
    use crate::db::DatabaseConnection;
    use secrecy::{ExposeSecret, SecretBox, SecretString};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub struct PostgresConnection {
        pub user: String,
        pub dbname: String,
        pub port: u16,
        pub password: SecretBox<String>,
        pub host: String,
        pub sslrootcert: Option<String>,
    }

    impl DatabaseConnection for PostgresConnection {
        fn connection_string(&self) -> SecretString {
            let connection_str = match self.sslrootcert {
                Some(ref sslcert) => format!(
                    "postgresql://{}:{}@{}:{}/{}?sslrootcert={}",
                    self.user,
                    self.password.expose_secret(),
                    self.host,
                    self.port,
                    self.dbname,
                    sslcert
                ),
                None => format!(
                    "postgresql://{}:{}@{}:{}/{}",
                    self.user,
                    self.password.expose_secret(),
                    self.host,
                    self.port,
                    self.dbname
                ),
            };
            connection_str.into()
        }
    }
}
