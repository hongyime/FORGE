//! Manifest-loader str/repr compatibility at the raw JSON boundary, not a Python runtime.
//! Raw tokens retain integer/float distinctions and object insertion order.
use serde::{
    Deserialize, Deserializer,
    de::{Error, MapAccess, Visitor},
};
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt};

pub(crate) fn coerce_and_strip(raw: &RawValue) -> Result<String, serde_json::Error> {
    Ok(render(raw, false, 0)?
        .trim_matches(|c: char| c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}'))
        .to_owned())
}

fn render(raw: &RawValue, repr: bool, depth: usize) -> Result<String, serde_json::Error> {
    // Match serde_json's normal nesting bound, including for a pre-built RawValue.
    if depth >= 128 {
        return Err(serde_json::Error::custom("manifest value nesting limit"));
    }
    let text = raw.get();
    match text.as_bytes().first() {
        Some(b'"') => {
            let value: String = serde_json::from_str(text)?;
            Ok(if repr { string_repr(&value) } else { value })
        }
        Some(b'[') => {
            let values: Vec<Box<RawValue>> = serde_json::from_str(text)?;
            let items = values
                .iter()
                .map(|v| render(v, true, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("[{}]", items.join(", ")))
        }
        Some(b'{') => {
            let object: OrderedObject = serde_json::from_str(text)?;
            let items = object
                .0
                .iter()
                .map(|(key, value)| {
                    render(value, true, depth + 1).map(|v| format!("{}: {v}", string_repr(key)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("{{{}}}", items.join(", ")))
        }
        Some(b'n') => Ok("None".into()),
        Some(b't') => Ok("True".into()),
        Some(b'f') => Ok("False".into()),
        _ => number_repr(text),
    }
}

fn number_repr(text: &str) -> Result<String, serde_json::Error> {
    if !text.contains(['.', 'e', 'E']) {
        // A validated JSON integer is already decimal; Python int discards negative zero.
        return Ok(if text == "-0" {
            "0".into()
        } else {
            text.into()
        });
    }
    let value: f64 = text
        .parse()
        .map_err(|_| serde_json::Error::custom("invalid manifest number"))?;
    let shortest = format!("{value:?}");
    match shortest.split_once('e') {
        Some((mantissa, exponent)) => {
            let exponent: i32 = exponent
                .parse()
                .map_err(|_| serde_json::Error::custom("invalid float exponent"))?;
            Ok(format!("{mantissa}e{exponent:+03}"))
        }
        None => Ok(shortest),
    }
}

fn string_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut output = String::new();
    output.push(quote);
    // Rust debug escaping protects a leading combining mark; Python repr leaves it printable.
    // A reusable ASCII prefix isolates Unicode printability from that debug-only rule.
    let mut probe = String::with_capacity(5);
    probe.push('a');
    for c in text.chars() {
        match c {
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c == quote => {
                output.push('\\');
                output.push(c);
            }
            '\'' | '"' => output.push(c),
            c => {
                probe.truncate(1);
                probe.push(c);
                if probe.escape_debug().skip(1).eq(std::iter::once(c)) {
                    output.push(c);
                } else {
                    let code = u32::from(c);
                    if code <= 0xff {
                        output.push_str(&format!("\\x{code:02x}"));
                    } else if code <= 0xffff {
                        output.push_str(&format!("\\u{code:04x}"));
                    } else {
                        output.push_str(&format!("\\U{code:08x}"));
                    }
                }
            }
        }
    }
    output.push(quote);
    output
}

struct OrderedObject(Vec<(String, Box<RawValue>)>);
impl<'de> Deserialize<'de> for OrderedObject {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = OrderedObject;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut entries: Vec<(String, Box<RawValue>)> = Vec::new();
                let mut positions: BTreeMap<String, usize> = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
                    if let Some(&index) = positions.get(&key) {
                        // json.loads replaces duplicate values without moving the first key.
                        entries[index].1 = value;
                    } else {
                        positions.insert(key.clone(), entries.len());
                        entries.push((key, value));
                    }
                }
                Ok(OrderedObject(entries))
            }
        }
        d.deserialize_map(ObjectVisitor)
    }
}
