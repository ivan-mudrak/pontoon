use types::{
    api_key::ApiKey,
    client::encrypt::EncryptedCredentials,
    secret::mask::Masked,
    user::{encrypt::EncryptedUser, UserId},
};

pub trait WalletRepository {
    fn get_credentials(
        &self,
        api_key: &Masked<ApiKey>,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<EncryptedCredentials>>> + Send;
    fn register_user(
        &self,
        api_key: Masked<ApiKey>,
        encrypted_user: EncryptedUser,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn get_user(
        &self,
        user_id: UserId,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<EncryptedUser>>> + Send;
    fn delete_user(
        &self,
        user_id: UserId,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}
