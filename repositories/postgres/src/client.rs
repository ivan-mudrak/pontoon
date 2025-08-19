use crate::PostgresPool;
use repositories::client::ClientRepository;
use types::client::{encrypt::EncryptedClient, ClientId};
use uuid::Uuid;

impl ClientRepository for PostgresPool {
    async fn create(&self, client: EncryptedClient) -> anyhow::Result<()> {
        sqlx::query(
            r#"
        WITH inserted_client AS (INSERT INTO clients (id, name) VALUES ($1, $2))
        INSERT INTO credentials (client_id, api_key, encrypted_secret, encrypted_data_key) VALUES ($1, $3, $4, $5)
        "#,
        )
        .bind::<Uuid>(client.id.into())
        .bind(client.name)
        .bind(client.credentials.api_key)
        .bind(client.credentials.encrypted_secret)
        .bind(client.credentials.encrypted_data_key)
        .execute(&self.pg_pool)
        .await?;
        Ok(())
    }

    async fn find(&self, client_id: ClientId) -> anyhow::Result<Option<EncryptedClient>> {
        let res = sqlx::query_as(
            r#"
        SELECT 
            clients.id,
            clients.name,
            credentials.api_key,
            credentials.encrypted_secret,
            credentials.encrypted_data_key
        FROM clients
        INNER JOIN credentials ON (credentials.client_id = clients.id)
        WHERE clients.id = $1
        "#,
        )
        .bind::<Uuid>(client_id.clone().into())
        .fetch_optional(&self.pg_pool)
        .await?;

        tracing::debug!("Find client by id '{:?}' result: {:?}", client_id, res);
        Ok(res)
    }
}
