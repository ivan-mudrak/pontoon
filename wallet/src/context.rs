use postgres_database::PostgresPool;
use serde::Deserialize;
use types::{
    config::ConfigReader,
    db::postgres::PostgresConnection,
    encrypt::master_key::{from_file, MasterKey},
};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub rust_log: String,
    pub port: u16,
    #[serde(deserialize_with = "from_file")]
    pub master_key: MasterKey,
    database: PostgresConnection,
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
