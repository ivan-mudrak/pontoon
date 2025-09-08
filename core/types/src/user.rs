use crate::encrypt::Aes256Key;
use crate::{encrypt::master_key::MasterKey, error::Error};
use rsa::{
    pkcs1v15,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    sha2::Sha256,
    signature::{Keypair, SignerMut, Verifier},
    RsaPrivateKey,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow, sqlx::Type)]
#[sqlx(transparent)]
#[serde(transparent)]
pub struct UserId(Uuid);

const NAMESPACE_USER: Uuid = Uuid::from_bytes([
    0x7a, 0x1c, 0x3e, 0x5b, 0x8d, 0x2f, 0x4c, 0x9a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
]);

impl From<&str> for UserId {
    fn from(str: &str) -> Self {
        UserId(Uuid::new_v5(&NAMESPACE_USER, str.as_bytes()))
    }
}

impl From<UserId> for String {
    fn from(user_id: UserId) -> Self {
        user_id.0.to_string()
    }
}

impl From<UserId> for Uuid {
    fn from(user_id: UserId) -> Self {
        user_id.0
    }
}

impl From<Uuid> for UserId {
    fn from(uuid: Uuid) -> Self {
        UserId(uuid)
    }
}

pub struct User {
    id: UserId,
    pub signing_key: SigningKey,
}

impl User {
    pub fn new() -> Result<Self, Error> {
        let signing_key = SigningKey::generate()?;
        let id = UserId::from(signing_key.public_key_pem()?.as_str());
        Ok(User { id, signing_key })
    }

    pub fn id(&self) -> &UserId {
        &self.id
    }

    pub fn encrypt(self, master_key: &MasterKey) -> Result<encrypt::EncryptedUser, Error> {
        let encrypted_signing_key = self.signing_key.encrypt(&master_key)?;

        Ok(encrypt::EncryptedUser {
            id: self.id,
            encrypted_signing_key,
        })
    }
}

pub struct SigningKey {
    pub private_key: RsaPrivateKey,
}

impl SigningKey {
    pub fn generate() -> Result<Self, Error> {
        tracing::debug!("Generating RSA key");
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        tracing::debug!("Generated RSA key");

        Ok(SigningKey { private_key })
    }

    pub fn public_key_pem(&self) -> Result<String, Error> {
        Ok(self
            .private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)?)
    }

    pub fn sign_message(&self, message: &str) -> String {
        let mut signing_key = pkcs1v15::SigningKey::<Sha256>::new(self.private_key.clone());
        signing_key.sign(message.as_bytes()).to_string()
    }

    pub fn verify_signature(&self, message: &str, signature: &[u8]) -> Result<bool, Error> {
        let signature =
            pkcs1v15::Signature::try_from(signature).map_err(|_| Error::InvalidSignature)?;
        let signing_key = pkcs1v15::SigningKey::<Sha256>::new(self.private_key.clone());
        let verifying_key = signing_key.verifying_key();
        let is_valid = verifying_key.verify(message.as_bytes(), &signature).is_ok();
        Ok(is_valid)
    }

    pub fn encrypt(&self, master_key: &MasterKey) -> Result<encrypt::EncryptedSigningKey, Error> {
        let data_key = Aes256Key::generate();

        let private_pem = self.private_key.to_pkcs8_pem(LineEnding::LF)?;

        let encrypted_private_key = data_key.encrypt(&private_pem)?;
        let encrypted_data_key = master_key.encrypt(&data_key.to_string())?;

        Ok(encrypt::EncryptedSigningKey {
            encrypted_private_key,
            encrypted_data_key,
        })
    }
}

pub mod encrypt {
    use super::*;
    use crate::encrypt::Aes256Key;
    use crate::{
        encrypt::{master_key::MasterKey, Encrypted},
        user::UserId,
    };
    use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
    use serde::Deserialize;
    use sqlx::{postgres::PgRow, FromRow, Row};
    use std::str::FromStr;

    #[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
    pub struct EncryptedUser {
        pub id: UserId,
        pub encrypted_signing_key: EncryptedSigningKey,
    }

    impl EncryptedUser {
        pub fn decrypt(self, master_key: &MasterKey) -> Result<User, Error> {
            let encrypted_signing_key = self.encrypted_signing_key.decrypt(master_key)?;
            Ok(User {
                id: self.id,
                signing_key: encrypted_signing_key,
            })
        }
    }

    impl<'r> FromRow<'r, PgRow> for EncryptedUser {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(EncryptedUser {
                id: row.try_get("id")?,
                encrypted_signing_key: EncryptedSigningKey {
                    encrypted_private_key: row.try_get("encrypted_private_key")?,
                    encrypted_data_key: row.try_get("encrypted_data_key")?,
                },
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, sqlx::FromRow, sqlx::Type)]
    pub struct EncryptedSigningKey {
        pub encrypted_private_key: Encrypted,
        pub encrypted_data_key: Encrypted,
    }

    impl EncryptedSigningKey {
        pub fn decrypt(self, master_key: &MasterKey) -> Result<SigningKey, Error> {
            let data_key_str = master_key.decrypt(&self.encrypted_data_key)?;
            let data_key = Aes256Key::from_str(&data_key_str)?;

            let private_pem = data_key.decrypt(&self.encrypted_private_key)?;
            let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem.as_str())?;

            Ok(SigningKey { private_key })
        }
    }
}
