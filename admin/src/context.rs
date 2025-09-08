use postgres_database::PostgresPool;
use serde::Deserialize;
use std::fmt::Debug;
use types::{
    config::ConfigReader,
    db::postgres::PostgresConnection,
    encrypt::master_key::{from_file, MasterKey},
};

#[derive(Deserialize)]
pub struct Config {
    pub rust_log: String,
    pub port: u16,
    #[serde(deserialize_with = "from_file")]
    pub master_key: MasterKey,
    database: PostgresConnection,
}

impl Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("port", &self.port)
            .field("rust_log", &self.rust_log)
            .finish()
    }
}

pub struct Context {
    pub config: Config,
    pub database: PostgresPool,
}

impl Context {
    pub async fn build() -> anyhow::Result<Self> {
        let config = Config::read_config()?;
        let database = PostgresPool::new(&config.database).await?;
        Ok(Self { config, database })
    }
}
