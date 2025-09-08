use crate::secret::mask::Maskable;
use secrecy::SerializableSecret;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, Zeroize, ZeroizeOnDrop)]
pub struct ApiKey([u8; 16]);

impl Serialize for ApiKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_uuid().to_string())
    }
}

impl<'de> Deserialize<'de> for ApiKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        let uuid = Uuid::parse_str(&str).map_err(D::Error::custom)?;
        Ok(uuid.into())
    }
}

pub mod postgres {
    use crate::api_key::ApiKey;
    use serde::ser::StdError;
    use sqlx::{
        encode::IsNull,
        postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef},
        Decode, Encode, Type,
    };
    use std::error::Error;
    use uuid::Uuid;

    impl Type<sqlx::Postgres> for ApiKey {
        fn type_info() -> PgTypeInfo {
            <uuid::Uuid as Type<sqlx::Postgres>>::type_info()
        }
        fn compatible(ty: &PgTypeInfo) -> bool {
            <uuid::Uuid as Type<sqlx::Postgres>>::compatible(ty)
        }
    }

    impl<'q> Encode<'q, sqlx::Postgres> for ApiKey {
        fn encode_by_ref(
            &self,
            buf: &mut PgArgumentBuffer,
        ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
            let uuid = self.to_uuid();
            <Uuid as Encode<sqlx::Postgres>>::encode_by_ref(&uuid, buf)
        }
    }

    impl<'r> Decode<'r, sqlx::Postgres> for ApiKey {
        fn decode(value: PgValueRef<'r>) -> Result<Self, Box<dyn StdError + Send + Sync>> {
            let uuid = <uuid::Uuid as Decode<sqlx::Postgres>>::decode(value)?;
            Ok(uuid.into())
        }
    }
}

impl SerializableSecret for ApiKey {}

impl ApiKey {
    pub fn to_uuid(&self) -> Uuid {
        Uuid::from_bytes(self.0)
    }
}

impl From<Uuid> for ApiKey {
    fn from(api_key: Uuid) -> Self {
        ApiKey(*api_key.as_bytes())
    }
}

impl From<ApiKey> for Uuid {
    fn from(api_key: ApiKey) -> Self {
        api_key.to_uuid()
    }
}

impl Maskable for ApiKey {
    fn mask(&self) -> String {
        format!("{}{}", &self.to_uuid().to_string()[..3], "***")
    }
}
