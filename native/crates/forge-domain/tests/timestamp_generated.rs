//! Input-derived calendar/clock oracle; bounded exhaustive products, no RNG/Python.
use forge_domain::timestamp::Timestamp;
use serde_json::json;

fn canonical(input: &str) -> Result<String, String> {
    let value: Timestamp = serde_json::from_value(json!(input)).map_err(|e| e.to_string())?;
    serde_json::from_value(serde_json::to_value(value).unwrap()).map_err(|e| e.to_string())
}

fn property(
    input: &str,
    expected: &str,
    adapter: impl Fn(&str) -> Result<String, String>,
) -> Result<(), String> {
    let first = adapter(input)?;
    if first != expected {
        return Err(format!(
            "preservation: {input:?} -> {first:?}, expected {expected:?}"
        ));
    }
    if adapter(&first)? != first {
        return Err(format!("idempotence: {input:?}"));
    }
    Ok(())
}

fn accepted(input: &str, expected: &str) {
    property(input, expected, canonical).unwrap();
    let parsed: Timestamp = serde_json::from_value(json!(input)).unwrap();
    let reparsed: Timestamp = serde_json::from_value(json!(canonical(input).unwrap())).unwrap();
    assert_eq!(parsed, reparsed, "typed local time/offset: {input:?}");
}

#[test]
fn generated_calendar_boundaries() {
    let mut counts = [0; 2];
    // 5 years x all 12 months x five day boundaries = 300 candidates.
    for year in [1, 1900, 2000, 2024, 9999] {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        for month in 1..=12 {
            let days = match month {
                2 => {
                    if leap {
                        29
                    } else {
                        28
                    }
                }
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            for day in [1, 28, 29, 30, 31] {
                let input = format!("{year:04}-{month:02}-{day:02}");
                if day <= days {
                    accepted(&input, &format!("{input}T00:00:00"));
                    counts[1] += 1;
                } else {
                    assert!(canonical(&input).is_err(), "{input}");
                    counts[0] += 1;
                }
            }
        }
    }
    assert_eq!(counts, [33, 267]);
    println!("Timestamp calendar generated: 300 cases; 267 accepted, 33 rejected");
}

#[test]
fn generated_clock_precision_and_offset_canonicalization() {
    // 2 days x 24 hours x 2 minutes x 2 seconds x 4 separators x 8
    // fraction widths x 9 offset spellings = 55,296 accepted inputs.
    let offsets = [
        ("", "", None),
        ("Z", "Z", Some(0)),
        ("z", "Z", Some(0)),
        ("+0000", "Z", Some(0)),
        ("-00:00", "Z", Some(0)),
        ("+05:30", "+05:30", Some(19800)),
        ("-0330", "-03:30", Some(-12600)),
        ("+2359", "+23:59", Some(86340)),
        ("-23:59", "-23:59", Some(-86340)),
    ];
    let mut count = 0;
    for day in 28..=29 {
        for hour in 0..24 {
            for minute in [0, 59] {
                for second in [0, 59] {
                    for separator in ['T', 't', ' ', '_'] {
                        for width in 0_u32..=7 {
                            let digit = (day + hour) % 9 + 1;
                            let digits = digit.to_string().repeat(width as usize);
                            let fraction = if width == 0 {
                                String::new()
                            } else {
                                format!("{}{digits}", if width % 2 == 0 { ',' } else { '.' })
                            };
                            // Decimal-place arithmetic from generated digits, not parsed output.
                            let micros: u32 =
                                (0..width.min(6)).map(|i| digit * 10_u32.pow(5 - i)).sum();
                            let canonical_fraction = if micros == 0 {
                                String::new()
                            } else {
                                format!(".{micros:06}")
                            };
                            for (offset, expected_offset, seconds) in offsets {
                                let clock = format!("{hour:02}:{minute:02}:{second:02}");
                                let input =
                                    format!("2024-02-{day}{separator}{clock}{fraction}{offset}");
                                let expected = format!(
                                    "2024-02-{day}T{clock}{canonical_fraction}{expected_offset}"
                                );
                                accepted(&input, &expected);
                                let parsed: Timestamp =
                                    serde_json::from_value(json!(input)).unwrap();
                                assert_eq!(parsed.local().microsecond(), micros, "{input}");
                                assert_eq!(
                                    parsed.offset().map(|o| o.whole_seconds()),
                                    seconds,
                                    "{input}"
                                );
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(count, 55_296);
    println!("Timestamp clock generated: {count} accepted cases; exhaustive, no seed");
}

#[test]
fn generated_invalid_clock_and_unicode() {
    let mut count = 0;
    // 24 indices x eight malformed constructions = 192 required rejections.
    for n in 0..24 {
        let unicode = ['é', '０', '界'][n % 3];
        for input in [
            format!("2024-02-29T{:02}:00:00", 24 + n),
            format!("2024-02-29T00:{:02}:00", 60 + n),
            format!("2024-02-29T00:00:{:02}", 60 + n),
            format!("2024-02-29T00:00:00+24:{n:02}"),
            format!("2024-02-29T00:00:00+00:{:02}", 60 + n),
            format!("2024-02-29{unicode}{n:02}:00:00"),
            format!("2024-02-29T{n:02}:00:00.{unicode}"),
            format!("2024-02-29T{n:02}:00:00+{unicode}1:00"),
        ] {
            assert!(canonical(&input).is_err(), "accepted {input:?}");
            count += 1;
        }
    }
    assert_eq!(count, 192);
    println!("Timestamp invalid generated: {count} rejected cases");
}

#[test]
fn preservation_oracle_rejects_idempotent_offset_erasure_adapter() {
    // Test-local fault injection: incorrect UTC relabeling, no instant conversion.
    fn broken(input: &str) -> Result<String, String> {
        canonical(input).map(|wire| match wire.strip_suffix("+05:30") {
            Some(local) => format!("{local}Z"),
            None => wire,
        })
    }
    let mut count = 0;
    for hour in 0..24 {
        let input = format!("2024-02-29t{hour:02}:00:00+0530");
        let expected = format!("2024-02-29T{hour:02}:00:00+05:30");
        let expected_broken = format!("2024-02-29T{hour:02}:00:00Z");
        let wire = broken(&input).unwrap();
        assert_eq!(broken(&wire).unwrap(), wire);
        let failure = property(&input, &expected, broken).unwrap_err();
        assert_eq!(
            failure,
            format!("preservation: {input:?} -> {expected_broken:?}, expected {expected:?}")
        );
        if hour == 0 {
            println!("Sensitivity first offset-erasure-adapter mismatch: {failure}");
        }
        count += 1;
    }
    assert_eq!(count, 24);
    println!("Sensitivity: {count} generated offset-erasure-adapter mismatches detected");
}
