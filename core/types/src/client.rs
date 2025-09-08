use crate::{
    api_key::ApiKey,
    encrypt::{master_key::MasterKey, Aes256Key, Encrypted},
    error::Error,
    secret::{
        mask::{expose_masked, Masked},
        redact::{expose_redacted, Redacted},
    },
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow, sqlx::Type)]
#[sqlx(transparent)]
#[serde(transparent)]
pub struct ClientId(Uuid);

const NAMESPACE_CLIENT: Uuid = Uuid::from_bytes([
    0x05, 0x40, 0xc0, 0xd2, 0x29, 0xab, 0x4a, 0x7e, 0x99, 0x1e, 0x45, 0xec, 0xe0, 0x0d, 0x92, 0x1a,
]);

impl From<&str> for ClientId {
    fn from(str: &str) -> Self {
        ClientId(Uuid::new_v5(&NAMESPACE_CLIENT, str.as_bytes()))
    }
}

impl From<ClientId> for String {
    fn from(client_id: ClientId) -> Self {
        client_id.0.to_string()
    }
}

impl From<ClientId> for Uuid {
    fn from(client_id: ClientId) -> Self {
        client_id.0
    }
}

impl From<Uuid> for ClientId {
    fn from(uuid: Uuid) -> Self {
        ClientId(uuid)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    id: ClientId,
    pub name: String,
    pub credentials: Credentials,
}

impl Client {
    pub fn new(name: String) -> Self {
        let credentials = Credentials::generate();
        let id = ClientId::from(name.as_str());
        Client {
            id,
            name,
            credentials,
        }
    }

    pub fn id(&self) -> &ClientId {
        &self.id
    }

    pub fn encrypt(&self, master_key: &MasterKey) -> Result<encrypt::EncryptedClient, Error> {
        let encrypted_credentials = self.credentials.encrypt(&master_key)?;

        Ok(encrypt::EncryptedClient {
            id: self.id.clone(),
            name: self.name.clone(),
            credentials: encrypted_credentials,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(serialize_with = "expose_masked")]
    pub api_key: Masked<ApiKey>,
    #[serde(serialize_with = "expose_redacted")]
    secret: Redacted<String>,
}

impl PartialEq for Credentials {
    fn eq(&self, other: &Self) -> bool {
        self.api_key.eq(&other.api_key)
    }
}

impl Eq for Credentials {}

impl Credentials {
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let encoded_secret = URL_SAFE_NO_PAD.encode(secret);

        Credentials {
            api_key: Masked::from(ApiKey::from(Uuid::new_v4())),
            secret: Redacted::from(encoded_secret),
        }
    }

    pub fn check_authentication(&self, message: &str, signature: &str) -> Result<(), Error> {
        tracing::debug!("Checking signature for a message: {}", message);

        let key = self.secret.expose().as_bytes();

        // Create a HMAC SHA-256 hasher
        let mut hasher =
            Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::InvalidSignature)?;

        // Update the hasher with the message
        hasher.update(message.as_bytes());

        // Verify provided signature
        // NOTE: It should be URL_SAFE_NO_PAD but most of online tools do STANDARD
        hasher
            .verify_slice(&STANDARD.decode(signature.as_bytes())?)
            .map_err(|_| Error::InvalidSignature)?;

        Ok(())
    }

    pub fn encrypt(&self, master_key: &MasterKey) -> Result<encrypt::EncryptedCredentials, Error> {
        let data_key = Aes256Key::generate();
        let encrypted_secret = data_key.encrypt(&self.secret.expose())?;
        let encrypted_data_key = master_key.encrypt(&data_key.to_string())?;

        Ok(encrypt::EncryptedCredentials {
            api_key: self.api_key.expose().to_owned().into(),
            encrypted_secret,
            encrypted_data_key,
        })
    }
}

pub mod encrypt {
    use super::*;
    use serde::Deserialize;
    use sqlx::{postgres::PgRow, FromRow, Row};
    use std::str::FromStr;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
    pub struct EncryptedClient {
        pub id: ClientId,
        pub name: String,
        pub credentials: EncryptedCredentials,
    }

    impl EncryptedClient {
        pub fn decrypt(self, master_key: &MasterKey) -> Result<Client, Error> {
            let credentials = self.credentials.decrypt(master_key)?;
            Ok(Client {
                id: self.id,
                name: self.name,
                credentials,
            })
        }
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow, sqlx::Type)]
    pub struct EncryptedCredentials {
        pub api_key: Masked<ApiKey>,
        pub encrypted_secret: Encrypted,
        pub encrypted_data_key: Encrypted,
    }

    impl EncryptedCredentials {
        pub fn decrypt(self, master_key: &MasterKey) -> Result<Credentials, Error> {
            let str = master_key.decrypt(&self.encrypted_data_key)?;
            let data_key = Aes256Key::from_str(&str)?;
            let secret = data_key.decrypt(&self.encrypted_secret)?;
            Ok(Credentials {
                api_key: self.api_key,
                secret: Redacted::from(secret),
            })
        }
    }

    impl<'r> FromRow<'r, PgRow> for encrypt::EncryptedClient {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(encrypt::EncryptedClient {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                credentials: encrypt::EncryptedCredentials {
                    api_key: row.try_get("api_key")?,
                    encrypted_secret: row.try_get("encrypted_secret")?,
                    encrypted_data_key: row.try_get("encrypted_data_key")?,
                },
            })
        }
    }
}
