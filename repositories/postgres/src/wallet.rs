use crate::PostgresPool;
use repositories::wallet::WalletRepository;
use types::{
    client::{encrypt::EncryptedCredentials, ApiKey},
    redact::Masked,
    user::{encrypt::EncryptedUser, UserId},
};
use uuid::Uuid;

impl WalletRepository for PostgresPool {
    async fn get_credentials(
        &self,
        api_key: &Masked<ApiKey>,
    ) -> anyhow::Result<Option<EncryptedCredentials>> {
        let res = sqlx::query_as("SELECT * FROM credentials WHERE api_key = $1")
            .bind::<Uuid>(api_key.inner_ref().clone().into())
            .fetch_optional(&self.pg_pool)
            .await?;

        Ok(res)
    }

    async fn register_user(
        &self,
        api_key: Masked<ApiKey>,
        encrypted_user: EncryptedUser,
    ) -> anyhow::Result<()> {
        let result = sqlx::query(
            r#"
        INSERT INTO users (id, client_id, encrypted_private_key, encrypted_data_key) 
        SELECT $1, credentials.client_id, $3, $4
        FROM credentials
        WHERE api_key = $2"#,
        )
        .bind(encrypted_user.id)
        .bind::<Uuid>(api_key.inner_ref().clone().into())
        .bind(encrypted_user.encrypted_signing_key.encrypted_private_key)
        .bind(encrypted_user.encrypted_signing_key.encrypted_data_key)
        .execute(&self.pg_pool)
        .await?;

        if result.rows_affected() == 0 {
            anyhow::bail!("User was not created");
        }
        Ok(())
    }

    async fn get_user(&self, user_id: UserId) -> anyhow::Result<Option<EncryptedUser>> {
        let res = sqlx::query_as(
            r#"
            SELECT 
                users.id, 
                users.encrypted_private_key,
                users.encrypted_data_key
            FROM users 
            INNER JOIN credentials USING (client_id)
            WHERE users.id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pg_pool)
        .await?;
        Ok(res)
    }

    async fn delete_user(&self, user_id: UserId) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&self.pg_pool)
            .await?;
        Ok(())
    }
}
