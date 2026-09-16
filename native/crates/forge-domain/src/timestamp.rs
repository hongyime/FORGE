//! Typed datetime wire values. Naive timestamps are never silently assigned UTC.
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};
use serde_json::Value;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp {
    local: PrimitiveDateTime,
    offset: Option<UtcOffset>,
}

impl Timestamp {
    pub fn now() -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            local: PrimitiveDateTime::new(now.date(), now.time()),
            offset: Some(UtcOffset::UTC),
        }
    }
    pub const fn local(self) -> PrimitiveDateTime {
        self.local
    }
    pub const fn offset(self) -> Option<UtcOffset> {
        self.offset
    }

    fn numeric(value: f64, python_float: bool) -> Option<Self> {
        let micros: i128 = if python_float {
            // Pydantic 2.10.4 floors whole seconds but uses absolute fractional micros,
            // even when the whole number is inferred as milliseconds. Preserve this asymmetry.
            let whole: i128 = format!("{:.0}", value.floor()).parse().ok()?;
            let fraction: i128 = format!("{:.0}", (value.fract().abs() * 1_000_000.0).round())
                .parse()
                .ok()?;
            let scale = if value.floor().abs() > 20_000_000_000.0 {
                1000
            } else {
                1_000_000
            };
            whole.checked_mul(scale)?.checked_add(fraction)?
        } else {
            let seconds = if value.abs() > 20_000_000_000.0 {
                value / 1000.0
            } else {
                value
            };
            format!("{:.0}", (seconds * 1_000_000.0).round())
                .parse()
                .ok()?
        };
        let date = OffsetDateTime::from_unix_timestamp_nanos(micros.checked_mul(1000)?).ok()?;
        if date.year() < 1 {
            return None;
        }
        Some(Self {
            local: PrimitiveDateTime::new(date.date(), date.time()),
            offset: Some(UtcOffset::UTC),
        })
    }

    fn text(value: &str) -> Option<Self> {
        if let Ok(number) = value.parse::<f64>() {
            return Self::numeric(number, false);
        }
        let date = value.get(..10)?;
        if date.get(4..5)? != "-"
            || date.get(7..8)? != "-"
            || date
                .bytes()
                .enumerate()
                .any(|(i, b)| !matches!(i, 4 | 7) && !b.is_ascii_digit())
        {
            return None;
        }
        let year = date.get(..4)?.parse::<i32>().ok()?;
        if year < 1 {
            return None;
        }
        let month = Month::try_from(date.get(5..7)?.parse::<u8>().ok()?).ok()?;
        let date = Date::from_calendar_date(year, month, date.get(8..10)?.parse().ok()?).ok()?;
        if value.len() == 10 {
            return Some(Self {
                local: date.midnight(),
                offset: None,
            });
        }
        if !matches!(value.get(10..11)?, "T" | "t" | " " | "_") {
            return None;
        }
        let rest = value.get(11..)?;
        let split = rest.find(['Z', 'z', '+', '-']).unwrap_or(rest.len());
        let clock = rest.get(..split)?;
        let suffix = rest.get(split..)?;
        let offset = match suffix {
            "" => None,
            "Z" | "z" => Some(UtcOffset::UTC),
            _ => {
                let sign = match suffix.get(..1)? {
                    "+" => 1,
                    "-" => -1,
                    _ => return None,
                };
                let hour_digits = suffix.get(1..3)?;
                let minute_digits = match suffix.len() {
                    5 => suffix.get(3..5)?,
                    6 if suffix.get(3..4)? == ":" => suffix.get(4..6)?,
                    _ => return None,
                };
                if !hour_digits
                    .bytes()
                    .chain(minute_digits.bytes())
                    .all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                let hours: i32 = hour_digits.parse().ok()?;
                let minutes: i32 = minute_digits.parse().ok()?;
                if hours >= 24 || minutes >= 60 {
                    return None;
                }
                Some(UtcOffset::from_whole_seconds(sign * (hours * 3600 + minutes * 60)).ok()?)
            }
        };
        let (hms, fraction) = clock.split_once(['.', ',']).unwrap_or((clock, ""));
        if clock.contains(['.', ',']) && fraction.is_empty() {
            return None;
        }
        let parts: Vec<&str> = hms.split(':').collect();
        if !(2..=3).contains(&parts.len())
            || parts.iter().any(|p| p.len() != 2)
            || (!fraction.is_empty() && parts.len() != 3)
        {
            return None;
        }
        if !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let hour = parts.first()?.parse().ok()?;
        let minute = parts.get(1)?.parse().ok()?;
        let second = parts.get(2).copied().unwrap_or("00").parse().ok()?;
        let digits: String = fraction.chars().take(6).collect();
        let microsecond = format!("{digits:0<6}").parse().ok()?;
        let clock = Time::from_hms_micro(hour, minute, second, microsecond).ok()?;
        Some(Self {
            local: PrimitiveDateTime::new(date, clock),
            offset,
        })
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let d = self.local;
        let mut output = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            d.year(),
            u8::from(d.month()),
            d.day(),
            d.hour(),
            d.minute(),
            d.second()
        );
        if d.microsecond() != 0 {
            output.push_str(&format!(".{:06}", d.microsecond()));
        }
        if let Some(offset) = self.offset {
            let seconds = offset.whole_seconds();
            if seconds == 0 {
                output.push('Z');
            } else {
                output.push_str(&format!(
                    "{}{:02}:{:02}",
                    if seconds < 0 { '-' } else { '+' },
                    seconds.abs() / 3600,
                    seconds.abs() % 3600 / 60
                ));
            }
        }
        s.serialize_str(&output)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let result = match Value::deserialize(d)? {
            Value::String(v) => Self::text(&v),
            Value::Number(v) => v
                .as_f64()
                .and_then(|number| Self::numeric(number, v.is_f64())),
            Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
        };
        result.ok_or_else(|| D::Error::custom("invalid datetime"))
    }
}
