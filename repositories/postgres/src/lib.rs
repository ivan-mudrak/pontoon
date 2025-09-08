pub mod client;
pub mod wallet;

use secrecy::ExposeSecret;
use types::db::DatabaseConnection;

pub struct PostgresPool {
    pub pg_pool: sqlx::PgPool,
}

impl PostgresPool {
    pub async fn new(settings: &impl DatabaseConnection) -> Result<Self, sqlx::Error> {
        let pg_pool = sqlx::PgPool::connect(&settings.connection_string().expose_secret()).await?;
        Ok(Self { pg_pool })
    }
}
