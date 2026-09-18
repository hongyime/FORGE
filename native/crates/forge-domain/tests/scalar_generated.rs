//! Exhaustive bounded grammars, not a fresh Python differential capture.
use forge_domain::{error::DomainError, ids::PluginId, scalars::C2Url};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use std::fmt::Debug;

// Enumerate every word of each requested length in base alphabet.len(). No RNG.
fn words(alphabet: &[char], min: u32, max: u32) -> Vec<String> {
    let mut output = Vec::new();
    for length in min..=max {
        for mut code in 0..alphabet.len().pow(length) {
            let mut word = String::new();
            for _ in 0..length {
                word.push(alphabet[code % alphabet.len()]);
                code /= alphabet.len();
            }
            output.push(word);
        }
    }
    output
}

fn canonical<T: DeserializeOwned + Serialize>(input: &str) -> Result<String, String> {
    let value: T = serde_json::from_value(json!(input)).map_err(|e| e.to_string())?;
    serde_json::from_value(serde_json::to_value(value).unwrap()).map_err(|e| e.to_string())
}

// Preservation is checked against INPUT, independently of idempotence.
fn property(input: &str, adapter: impl Fn(&str) -> Result<String, String>) -> Result<(), String> {
    let first = adapter(input)?;
    if first != input {
        return Err(format!("preservation: {input:?} -> {first:?}"));
    }
    if adapter(&first)? != first {
        return Err(format!("idempotence: {input:?}"));
    }
    Ok(())
}

fn check<T: DeserializeOwned + Serialize + PartialEq + Debug>(
    input: &str,
    accepted: bool,
    constructor: fn(String) -> Result<T, DomainError>,
    error: DomainError,
) {
    let direct = constructor(input.into());
    let wire = serde_json::from_value::<T>(json!(input));
    if accepted {
        let direct = direct.unwrap_or_else(|e| panic!("{input:?}: {e}"));
        assert_eq!(wire.unwrap(), direct, "{input:?}");
        assert_eq!(serde_json::to_value(&direct).unwrap(), json!(input));
        assert_eq!(constructor(input.into()).unwrap(), direct);
        property(input, canonical::<T>).unwrap();
    } else {
        assert_eq!(direct.unwrap_err(), error, "{input:?}");
        assert!(wire.is_err(), "accepted {input:?}");
    }
}

#[test]
fn generated_c2_identity_and_rejection() {
    // 155 words: all length 1..=3 over five legal alias characters.
    // Seven accepted and six rejected constructions per word, plus two empties.
    let mut counts = [0; 2];
    let mut exercise = |input: String, accepted: bool| {
        check(&input, accepted, C2Url::new, DomainError::InvalidC2Url);
        counts[usize::from(accepted)] += 1;
    };
    for word in words(&['a', 'Z', '0', '.', '-'], 1, 3) {
        for input in [
            word.clone(),
            format!("{word}\n"),
            format!("https://{word}"),
            format!("https://{word}/é"),
            format!("https://{word}\n/é"),
            format!("https:// {word}"),
            format!("https://界/{word}"),
        ] {
            exercise(input, true);
        }
        for input in [
            format!("http://{word}"),
            format!("HTTPS://{word}"),
            format!("{word}/é"),
            format!("{word}\n\n"),
            format!("https://\n{word}"),
            format!(" {word}"),
        ] {
            exercise(input, false);
        }
    }
    exercise(String::new(), false);
    exercise("https://".into(), false);
    assert_eq!(counts, [932, 1085]);
    println!("C2Url generated: 2017 cases; 1085 accepted, 932 rejected; exhaustive, no seed");
}

#[test]
fn generated_plugin_identity_and_rejection() {
    let mut counts = [0; 2];
    let mut exercise = |input: String, accepted: bool| {
        check(
            &input,
            accepted,
            PluginId::new,
            DomainError::InvalidPluginId,
        );
        counts[usize::from(accepted)] += 1;
    };
    // 2 first characters x (5^2 + 5^3) suffixes = 300 valid tails.
    for first in ['a', '0'] {
        for suffix in words(&['a', '0', '.', '_', '-'], 2, 3) {
            let tail = format!("{first}{suffix}");
            for ending in ["", "\n"] {
                exercise(format!("plugin_{tail}{ending}"), true);
            }
            for input in [
                format!("plugin_{tail}\n\n"),
                format!("Plugin_{tail}"),
                format!("plugin_.{tail}"),
                format!("plugin_A{tail}"),
                format!("plugin_{tail}é"),
                format!("plugin_{tail}\0"),
            ] {
                exercise(input, false);
            }
        }
    }
    // Exhaust every tail length 0..=65, including both sides of 3 and 64.
    for length in 0..=65 {
        for ending in ["", "\n"] {
            exercise(
                format!("plugin_{}{ending}", "a".repeat(length)),
                (3..=64).contains(&length),
            );
        }
    }
    assert_eq!(counts, [1808, 724]);
    println!("PluginId generated: 2532 cases; 724 accepted, 1808 rejected; exhaustive, no seed");
}

#[test]
fn preservation_oracle_rejects_idempotent_trimming_adapters() {
    // Test-local fault injection, NOT a production-source mutation.
    fn trimmed<T: DeserializeOwned + Serialize>(input: &str) -> Result<String, String> {
        canonical::<T>(input).map(|wire| wire.trim_end().to_owned())
    }
    let mut counts = [0; 2];
    for word in words(&['a', 'Z', '0', '.', '-'], 1, 3) {
        let input = format!("{word}\n");
        let broken = trimmed::<C2Url>(&input).unwrap();
        assert_eq!(trimmed::<C2Url>(&broken).unwrap(), broken);
        assert_eq!(
            property(&input, trimmed::<C2Url>).unwrap_err(),
            format!("preservation: {input:?} -> {word:?}")
        );
        counts[0] += 1;
    }
    for first in ['a', '0'] {
        for suffix in words(&['a', '0', '.', '_', '-'], 2, 3) {
            let expected_broken = format!("plugin_{first}{suffix}");
            let input = format!("{expected_broken}\n");
            let broken = trimmed::<PluginId>(&input).unwrap();
            assert_eq!(trimmed::<PluginId>(&broken).unwrap(), broken);
            assert_eq!(
                property(&input, trimmed::<PluginId>).unwrap_err(),
                format!("preservation: {input:?} -> {expected_broken:?}")
            );
            counts[1] += 1;
        }
    }
    assert_eq!(counts, [155, 300]);
    println!(
        "Sensitivity: 155 C2 + 300 PluginId trimming-adapter mismatches detected; first cases: {:?}; {:?}",
        property("a\n", trimmed::<C2Url>).unwrap_err(),
        property("plugin_aaa\n", trimmed::<PluginId>).unwrap_err()
    );
}
