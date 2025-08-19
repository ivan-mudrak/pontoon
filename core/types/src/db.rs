pub trait DatabaseConnection {
    fn connection_string(&self) -> String;
}

pub mod postgres {
    use crate::{db::DatabaseConnection, redact::Redacted};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct PostgresConnection {
        pub user: String,
        pub dbname: String,
        pub port: u16,
        pub password: Redacted<String>,
        pub host: String,
        pub sslrootcert: Option<String>,
    }

    impl DatabaseConnection for PostgresConnection {
        fn connection_string(&self) -> String {
            match self.sslrootcert {
                Some(ref sslcert) => format!(
                    "postgresql://{}:{}@{}:{}/{}?sslrootcert={}",
                    self.user,
                    self.password.inner_ref(),
                    self.host,
                    self.port,
                    self.dbname,
                    sslcert
                ),
                None => format!(
                    "postgresql://{}:{}@{}:{}/{}",
                    self.user,
                    self.password.inner_ref(),
                    self.host,
                    self.port,
                    self.dbname
                ),
            }
        }
    }
}
