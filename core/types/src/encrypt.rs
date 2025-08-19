use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Encrypted {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Into<String> for Encrypted {
    fn into(self) -> String {
        format!(
            "{}:{}",
            URL_SAFE_NO_PAD.encode(self.nonce),
            URL_SAFE_NO_PAD.encode(self.ciphertext)
        )
    }
}

impl TryInto<Encrypted> for String {
    type Error = base64::DecodeError;

    fn try_into(self) -> Result<Encrypted, Self::Error> {
        let parts: Vec<&str> = self.split(':').collect();
        if parts.len() != 2 {
            return Err(base64::DecodeError::InvalidLength);
        }
        let nonce = URL_SAFE_NO_PAD.decode(parts[0])?;
        let ciphertext = URL_SAFE_NO_PAD.decode(parts[1])?;
        Ok(Encrypted { nonce, ciphertext })
    }
}

pub mod postgres {
    use crate::encrypt::Encrypted;
    use sqlx::{
        encode::IsNull,
        postgres::{PgArgumentBuffer, PgValueRef},
        Decode, Encode, Postgres, Type,
    };
    use std::error::Error;

    impl Type<Postgres> for Encrypted {
        fn type_info() -> sqlx::postgres::PgTypeInfo {
            <String as Type<Postgres>>::type_info()
        }
    }

    impl<'q> Encode<'q, Postgres> for Encrypted {
        fn encode_by_ref(
            &self,
            buf: &mut PgArgumentBuffer,
        ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
            let str: String = self.clone().into();
            <String as Encode<Postgres>>::encode_by_ref(&str, buf)
        }
    }

    impl<'r> Decode<'r, Postgres> for Encrypted {
        fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
            let s = <String as Decode<Postgres>>::decode(value)?;
            let enc: Encrypted = s
                .try_into()
                .map_err(|e| sqlx::error::BoxDynError::from(e))?;
            Ok(enc)
        }
    }
}

pub mod data_key {
    use crate::{encrypt::Encrypted, error::Error, redact::Redacted};
    use aes_gcm::{
        aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm, KeySizeUser,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use std::str::FromStr;

    pub struct DataEncryptionKey {
        key: Redacted<GenericArray<u8, <Aes256Gcm as KeySizeUser>::KeySize>>,
        pub cipher: Redacted<Aes256Gcm>,
    }

    impl DataEncryptionKey {
        pub fn generate() -> Self {
            let key = Aes256Gcm::generate_key(OsRng);
            let cipher = Aes256Gcm::new(&key);
            Self {
                key: Redacted::from(key),
                cipher: Redacted::from(cipher),
            }
        }

        pub fn encrypt(&self, data: &str) -> Result<Encrypted, Error> {
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
            let ciphertext = self.cipher.inner_ref().encrypt(&nonce, data.as_bytes())?;

            Ok(Encrypted {
                nonce: nonce.to_vec(),
                ciphertext,
            })
        }

        pub fn decrypt(&self, encrypted: &Encrypted) -> Result<String, Error> {
            let nonce = GenericArray::from_slice(&encrypted.nonce);
            let plaintext = self
                .cipher
                .inner_ref()
                .decrypt(&nonce, encrypted.ciphertext.as_ref())?;
            Ok(String::from_utf8(plaintext)?)
        }
    }

    impl FromStr for DataEncryptionKey {
        type Err = Error;

        fn from_str(str: &str) -> Result<Self, Self::Err> {
            let bytes = URL_SAFE_NO_PAD.decode(str)?;
            let key = GenericArray::from_slice(&bytes);
            let cipher = Aes256Gcm::new(key);

            Ok(Self {
                key: Redacted::from(key.to_owned()),
                cipher: Redacted::from(cipher),
            })
        }
    }

    impl ToString for DataEncryptionKey {
        fn to_string(&self) -> String {
            URL_SAFE_NO_PAD.encode(self.key.inner_ref().as_slice())
        }
    }
}

pub mod master_key {
    use crate::{encrypt::Encrypted, env, error::Error, redact::Redacted};
    use aes_gcm::{
        aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm, Key,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use std::str::FromStr;

    #[derive(Debug, Clone)]
    pub struct MasterKey {
        pub cipher: Redacted<Aes256Gcm>,
    }

    pub fn from_file<'de, D>(deserializer: D) -> Result<MasterKey, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let file_path = <String as serde::Deserialize>::deserialize(deserializer)?;
        MasterKey::from_file(file_path).map_err(|err| serde::de::Error::custom(err))
    }

    impl FromStr for MasterKey {
        type Err = Error;

        fn from_str(str: &str) -> Result<Self, Self::Err> {
            let bytes = URL_SAFE_NO_PAD.decode(str)?;
            let key = Key::<Aes256Gcm>::from_slice(&bytes);
            let cipher = Aes256Gcm::new(&key);

            Ok(Self {
                cipher: Redacted::from(cipher),
            })
        }
    }

    impl MasterKey {
        pub fn from_env() -> Result<Self, Error> {
            let str = env::read_from_env_file::<String>("MASTER_KEY")?;
            MasterKey::from_str(&str)
        }

        pub fn from_file(file_path: String) -> Result<Self, Error> {
            let str = env::read_file(&file_path)?;
            MasterKey::from_str(&str)
        }

        pub fn encrypt(&self, data: &str) -> Result<Encrypted, Error> {
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
            let ciphertext = self.cipher.inner_ref().encrypt(&nonce, data.as_bytes())?;

            Ok(Encrypted {
                nonce: nonce.to_vec(),
                ciphertext,
            })
        }

        pub fn decrypt(&self, encrypted: &Encrypted) -> Result<String, Error> {
            let nonce = GenericArray::from_slice(&encrypted.nonce);
            let plaintext = self
                .cipher
                .inner_ref()
                .decrypt(&nonce, encrypted.ciphertext.as_ref())?;
            Ok(String::from_utf8(plaintext)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::data_key::*;

    #[test]
    fn test_data_encryption_key_encrypt_decrypt() {
        let key = DataEncryptionKey::generate();
        let plaintext = "The quick brown fox jumps over the lazy dog.";
        let encrypted = key.encrypt(plaintext).expect("encryption failed");
        let decrypted = key.decrypt(&encrypted).expect("decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_data_encryption_key_encrypt_decrypt_with_conversion() {
        let key = DataEncryptionKey::generate();
        let plaintext = "The quick brown fox jumps over the lazy dog.";
        let encrypted = key.encrypt(plaintext).expect("encryption failed");
        let encrypted_str: String = encrypted.into();
        let encrypted_from_str = encrypted_str
            .try_into()
            .expect("string to encrypted failed");

        let decrypted = key.decrypt(&encrypted_from_str).expect("decryption failed");
        assert_eq!(decrypted, plaintext);
    }
}
