pub mod redact {
    use secrecy::{ExposeSecret, SecretBox};
    use serde::{Deserialize, Serialize, Serializer};
    use std::fmt::{self, Debug, Display, Formatter};
    use zeroize::Zeroize;

    pub const REDACTED: &str = "[REDACTED]";

    pub struct Redacted<T: Zeroize>(SecretBox<T>);

    impl<T: Zeroize> Redacted<T> {
        #[inline]
        pub fn new(value: T) -> Self {
            Self(SecretBox::new(Box::new(value)))
        }

        #[inline]
        pub fn expose(&self) -> &T {
            self.0.expose_secret()
        }

        #[inline]
        pub fn into_secret(self) -> SecretBox<T> {
            self.0
        }
    }

    impl<T: Zeroize> From<T> for Redacted<T> {
        fn from(value: T) -> Self {
            Redacted::new(value)
        }
    }

    impl<'de, T: Zeroize + Deserialize<'de>> Deserialize<'de> for Redacted<T> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            T::deserialize(deserializer).map(Redacted::new)
        }
    }

    // A wrapper type for masking sensitive information in logs and outputs.
    impl<T: Zeroize> Debug for Redacted<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str(REDACTED)
        }
    }
    impl<T: Zeroize> Display for Redacted<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str(REDACTED)
        }
    }

    impl<T: Zeroize> Serialize for Redacted<T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(REDACTED)
        }
    }

    pub fn expose_redacted<T: Zeroize + Serialize, S>(
        redacted_secret: &Redacted<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        redacted_secret.expose().serialize(serializer)
    }
}

pub mod mask {
    use secrecy::{ExposeSecret, SecretBox};
    use serde::{Deserialize, Serialize, Serializer};
    use std::fmt::{self, Debug, Display, Formatter};
    use zeroize::Zeroize;

    pub trait Maskable {
        fn mask(&self) -> String;
    }

    pub trait MaskableSecret: Maskable + Zeroize {}
    impl<T: Maskable + Zeroize> MaskableSecret for T {}

    pub struct Masked<T: MaskableSecret>(SecretBox<T>);

    impl<T: MaskableSecret + PartialEq> PartialEq for Masked<T> {
        fn eq(&self, other: &Self) -> bool {
            self.0.expose_secret().eq(&other.0.expose_secret())
        }
    }

    impl<T: MaskableSecret + Eq> Eq for Masked<T> {}

    impl<T: MaskableSecret> Masked<T> {
        #[inline]
        pub fn new(value: T) -> Self {
            Self(SecretBox::new(Box::new(value)))
        }

        #[inline]
        pub fn expose(&self) -> &T {
            self.0.expose_secret()
        }
    }

    impl<T: MaskableSecret> From<T> for Masked<T> {
        fn from(value: T) -> Self {
            Masked::new(value)
        }
    }

    impl<T: MaskableSecret> Debug for Masked<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0.expose_secret().mask())
        }
    }
    impl<T: MaskableSecret> Display for Masked<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0.expose_secret().mask())
        }
    }

    impl<T: MaskableSecret> Serialize for Masked<T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&self.0.expose_secret().mask())
        }
    }

    pub fn expose_masked<T: MaskableSecret + Serialize, S>(
        masked_secret: &Masked<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        masked_secret.expose().serialize(serializer)
    }

    impl<'de, T: MaskableSecret + Deserialize<'de>> Deserialize<'de> for Masked<T> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            T::deserialize(deserializer).map(Masked::new)
        }
    }

    pub mod postgres {
        use crate::secret::mask::{MaskableSecret, Masked};
        use secrecy::ExposeSecret;
        use sqlx::{
            encode::IsNull,
            postgres::{PgArgumentBuffer, PgValueRef},
            Decode, Encode, Postgres, Type,
        };
        use std::error::Error;

        impl<T: MaskableSecret + sqlx::Type<Postgres>> Type<Postgres> for Masked<T> {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                <T as Type<Postgres>>::type_info()
            }
        }

        impl<'q, T: MaskableSecret + sqlx::Encode<'q, Postgres>> Encode<'q, Postgres> for Masked<T> {
            fn encode_by_ref(
                &self,
                buf: &mut PgArgumentBuffer,
            ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
                <T as Encode<Postgres>>::encode_by_ref(&self.0.expose_secret(), buf)
            }
        }

        impl<'r, T: MaskableSecret + sqlx::Decode<'r, Postgres>> Decode<'r, Postgres> for Masked<T> {
            fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
                <T as Decode<Postgres>>::decode(value).map(|val| Masked::new(val))
            }
        }
    }
}
