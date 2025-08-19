use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};

/// A wrapper type for redacting sensitive information in logs and outputs.
/// This type is used to ensure that sensitive data is not logged or displayed,
/// replacing it with a constant "REDACTED" string.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Redacted<T>(T);

pub const REDACTED: &str = "[REDACTED]";

impl<T> Debug for Redacted<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", REDACTED)
    }
}

impl<T> Display for Redacted<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", REDACTED)
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(value: T) -> Self {
        Redacted(value)
    }
}

impl<T> Redacted<T> {
    pub fn inner_ref(&self) -> &T {
        &self.0
    }
}

// A wrapper type for masking sensitive information in logs and outputs.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::FromRow, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct Masked<T: Maskable>(T);

impl<T: Maskable> From<T> for Masked<T> {
    fn from(value: T) -> Self {
        Masked(value)
    }
}

pub trait Maskable {
    fn mask(&self) -> String;
}

impl<T: Maskable> Debug for Masked<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.mask())
    }
}

impl<T: Maskable> Display for Masked<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.mask())
    }
}

impl<T: Maskable> Masked<T> {
    pub fn inner_ref(&self) -> &T {
        &self.0
    }
}
