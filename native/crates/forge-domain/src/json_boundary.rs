//! Pydantic's lax JSON scalar boundary, separated from strict SQL primitives.
use crate::{error::DomainError, ids::EngagementId};
use serde::{Deserialize, Deserializer, Serialize, de::Error};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Integer<const MIN: i64, const MAX: i64>(i64);
pub type JsonInt = Integer<{ i64::MIN }, { i64::MAX }>;

impl<const MIN: i64, const MAX: i64> Integer<MIN, MAX> {
    pub const fn constant<const VALUE: i64>() -> Self {
        const {
            assert!(VALUE >= MIN && VALUE <= MAX);
        }
        Self(VALUE)
    }
    pub const fn new(value: i64) -> Result<Self, DomainError> {
        if value < MIN || value > MAX {
            Err(DomainError::OutOfRange { field: "integer" })
        } else {
            Ok(Self(value))
        }
    }
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl<'de, const MIN: i64, const MAX: i64> Deserialize<'de> for Integer<MIN, MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(d)?;
        let integer = match value {
            Value::Bool(v) => Some(i64::from(v)),
            Value::Number(v) => v.as_i64().or_else(|| v.as_f64().and_then(integral_float)),
            Value::String(v) => integer_string(&v),
            Value::Null | Value::Array(_) | Value::Object(_) => None,
        }
        .ok_or_else(|| D::Error::custom("invalid integer"))?;
        Self::new(integer).map_err(D::Error::custom)
    }
}

fn integral_float(value: f64) -> Option<i64> {
    if value.is_finite() && value.fract() == 0.0 {
        format!("{value:.0}").parse().ok()
    } else {
        None
    }
}

fn integer_string(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    let (whole, fraction) = trimmed.split_once('.').unwrap_or((trimmed, ""));
    if trimmed.contains('.') && (fraction.is_empty() || !fraction.bytes().all(|c| c == b'0')) {
        return None;
    }
    let digits = whole.strip_prefix(['+', '-']).unwrap_or(whole);
    if !digits
        .split('_')
        .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    whole.replace('_', "").parse().ok()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct JsonBool(bool);
impl JsonBool {
    pub const fn new(value: bool) -> Self {
        Self(value)
    }
    pub const fn get(self) -> bool {
        self.0
    }
}
impl<'de> Deserialize<'de> for JsonBool {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let parsed = match Value::deserialize(d)? {
            Value::Bool(v) => Some(v),
            Value::Number(v) => match v.as_f64() {
                Some(0.0) => Some(false),
                Some(1.0) => Some(true),
                _ => None,
            },
            Value::String(v) => match v.to_ascii_lowercase().as_str() {
                "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
                "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
                _ => None,
            },
            Value::Null | Value::Array(_) | Value::Object(_) => None,
        };
        parsed
            .map(Self)
            .ok_or_else(|| D::Error::custom("invalid boolean"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(transparent)]
pub struct JsonFloat(f64);
impl JsonFloat {
    pub const fn get(self) -> f64 {
        self.0
    }
}
impl<'de> Deserialize<'de> for JsonFloat {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let parsed = match Value::deserialize(d)? {
            Value::Bool(v) => Some(f64::from(v)),
            Value::Number(v) => v.as_f64(),
            Value::String(v) => {
                let text = v.trim();
                let bytes = text.as_bytes();
                let valid = bytes
                    .iter()
                    .enumerate()
                    .filter(|(_, b)| **b == b'_')
                    .all(|(i, _)| {
                        i > 0
                            && i + 1 < bytes.len()
                            && bytes[i - 1].is_ascii_digit()
                            && bytes[i + 1].is_ascii_digit()
                    });
                if valid {
                    text.replace('_', "").parse().ok()
                } else {
                    None
                }
            }
            Value::Null | Value::Array(_) | Value::Object(_) => None,
        };
        parsed
            .map(Self)
            .ok_or_else(|| D::Error::custom("invalid float"))
    }
}

pub fn engagement<'de, D: Deserializer<'de>>(d: D) -> Result<EngagementId, D::Error> {
    JsonInt::deserialize(d).map(|v| EngagementId::new(v.get()))
}

/// Unlike serde's implicit Option default, this requires the key, but accepts null.
pub fn required_nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

pub fn provided<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}
