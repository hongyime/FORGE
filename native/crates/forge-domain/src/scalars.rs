use crate::error::DomainError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Label<const MAX: usize>(String);
impl<const MAX: usize> Label<MAX> {
    pub fn new(value: String) -> Result<Self, DomainError> {
        if value.chars().count() > MAX {
            return Err(DomainError::TooLong { max_chars: MAX });
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<const MAX: usize> TryFrom<String> for Label<MAX> {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl<const MAX: usize> From<Label<MAX>> for String {
    fn from(value: Label<MAX>) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct EdgeWeight(f64);
impl EdgeWeight {
    pub fn new(value: f64) -> Result<Self, DomainError> {
        if !(0.0..=200.0).contains(&value) {
            return Err(DomainError::OutOfRange { field: "weight" });
        }
        Ok(Self(value))
    }
    pub fn get(self) -> f64 {
        self.0
    }
}
impl TryFrom<f64> for EdgeWeight {
    type Error = DomainError;
    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<EdgeWeight> for f64 {
    fn from(value: EdgeWeight) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct NonNegativeCount(i64);
impl NonNegativeCount {
    pub fn new(value: i64) -> Result<Self, DomainError> {
        if value < 0 {
            return Err(DomainError::OutOfRange { field: "count" });
        }
        Ok(Self(value))
    }
    pub fn get(self) -> i64 {
        self.0
    }
}
impl TryFrom<i64> for NonNegativeCount {
    type Error = DomainError;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<NonNegativeCount> for i64 {
    fn from(value: NonNegativeCount) -> Self {
        value.0
    }
}

/// Only the source C2 URL field validator; no transport, resolution, or normalization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct C2Url(String);
impl C2Url {
    pub fn new(value: String) -> Result<Self, DomainError> {
        let https = value
            .strip_prefix("https://")
            .is_some_and(|tail| !tail.is_empty() && !tail.starts_with('\n'));
        let bare = value.strip_suffix('\n').unwrap_or(&value);
        let alias = !bare.is_empty()
            && bare
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b));
        if https || alias {
            Ok(Self(value))
        } else {
            Err(DomainError::InvalidC2Url)
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for C2Url {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<C2Url> for String {
    fn from(value: C2Url) -> Self {
        value.0
    }
}
