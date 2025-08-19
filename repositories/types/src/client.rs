use types::client::{encrypt::EncryptedClient, ClientId};

pub trait ClientRepository {
    fn create(
        &self,
        client: EncryptedClient,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn find(
        &self,
        client_id: ClientId,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<EncryptedClient>>> + Send;
    fn find_by_name(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<EncryptedClient>>> + Send {
        self.find(ClientId::from(name))
    }
}
