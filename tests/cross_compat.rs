use ksuid::Ksuid;

/// Test vectors from the Go/TypeScript reference implementations.
/// Each entry: (timestamp: u32, payload_hex: &str, expected_string: &str, raw_hex: &str)
const TEST_VECTORS: &[(u32, &str, &str, &str)] = &[
    (
        0,
        "00000000000000000000000000000000",
        "000000000000000000000000000",
        "0000000000000000000000000000000000000000",
    ),
    (
        4294967295,
        "ffffffffffffffffffffffffffffffff",
        "aWgEPTl1tmebfsQzFP4bxwgy80V",
        "ffffffffffffffffffffffffffffffffffffffff",
    ),
    (
        95004740,
        "669f7efd7b6fe812278486085878563d",
        "0o5sKzFDBc56T8mbUP8wH1KpSX7",
        "05a9a844669f7efd7b6fe812278486085878563d",
    ),
    (
        95004740,
        "00000000000000000000000000000000",
        "0o5sKw7Z4xnYVLXEmaUv9lxG0C8",
        "05a9a84400000000000000000000000000000000",
    ),
    (
        95004740,
        "ffffffffffffffffffffffffffffffff",
        "0o5sL3ud7B3uapD0WkI3wf4VhoF",
        "05a9a844ffffffffffffffffffffffffffffffff",
    ),
    (
        0,
        "0123456789abcdef0123456789abcdef",
        "000000296tiiBb3U904RIpygpjj",
        "000000000123456789abcdef0123456789abcdef",
    ),
    (
        2147483647,
        "deadbeefdeadbeefdeadbeefdeadbeef",
        "IGL7CirdbzjSOihuGRwhdVqH3mh",
        "7fffffffdeadbeefdeadbeefdeadbeefdeadbeef",
    ),
    (
        0,
        "deadbeefdeadbeefdeadbeefdeadbeef",
        "000006mBhJfVeGABNuCXRQc2hOZ",
        "00000000deadbeefdeadbeefdeadbeefdeadbeef",
    ),
    (
        4294967295,
        "abcdef0123456789abcdef0123456789",
        "aWgEPRC9f9y39AiMcAMCXnpvSIr",
        "ffffffffabcdef0123456789abcdef0123456789",
    ),
];

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_cross_compat_encode() {
    for (ts, payload_hex, expected_str, _raw_hex) in TEST_VECTORS {
        let payload_bytes = hex_to_bytes(payload_hex);
        let payload: [u8; 16] = payload_bytes.try_into().unwrap();
        let k = Ksuid::from_parts(*ts, &payload);
        assert_eq!(
            k.to_string(),
            *expected_str,
            "encode failed for ts={}, payload={}",
            ts,
            payload_hex
        );
    }
}

#[test]
fn test_cross_compat_decode() {
    for (expected_ts, expected_payload_hex, string, _raw_hex) in TEST_VECTORS {
        let k = Ksuid::parse(string).unwrap_or_else(|_| panic!("failed to parse {}", string));
        assert_eq!(
            k.timestamp(),
            *expected_ts,
            "timestamp mismatch for {}",
            string
        );
        let expected_payload = hex_to_bytes(expected_payload_hex);
        assert_eq!(
            k.payload().as_slice(),
            expected_payload.as_slice(),
            "payload mismatch for {}",
            string
        );
    }
}

#[test]
fn test_cross_compat_roundtrip() {
    for (_ts, _payload_hex, string, _raw_hex) in TEST_VECTORS {
        let k = Ksuid::parse(string).unwrap();
        assert_eq!(k.to_string(), *string, "roundtrip failed for {}", string);
    }
}

#[test]
fn test_cross_compat_raw_bytes() {
    for (ts, payload_hex, _string, raw_hex) in TEST_VECTORS {
        let raw_bytes = hex_to_bytes(raw_hex);
        let raw: [u8; 20] = raw_bytes.try_into().unwrap();
        let k = Ksuid::from_bytes(&raw);
        assert_eq!(k.timestamp(), *ts, "raw bytes timestamp mismatch");
        let expected_payload = hex_to_bytes(payload_hex);
        assert_eq!(
            k.payload().as_slice(),
            expected_payload.as_slice(),
            "raw bytes payload mismatch"
        );
    }
}

#[test]
fn test_cross_compat_next_prev() {
    // From TypeScript test vectors
    let k = Ksuid::parse("0o5sKzFDBc56T8mbUP8wH1KpSX7").unwrap();
    assert_eq!(k.next().to_string(), "0o5sKzFDBc56T8mbUP8wH1KpSX8");
    assert_eq!(k.prev().to_string(), "0o5sKzFDBc56T8mbUP8wH1KpSX6");

    // NIL wraps
    assert_eq!(
        Ksuid::NIL.prev().to_string(),
        "aWgEPTl1tmebfsQzFP4bxwgy80V",
        "NIL.prev() should wrap to MAX"
    );
    assert_eq!(
        Ksuid::NIL.next().to_string(),
        "000000000000000000000000001",
        "NIL.next() should be 1"
    );
    assert_eq!(
        Ksuid::MAX.next().to_string(),
        "000000000000000000000000000",
        "MAX.next() should wrap to NIL"
    );
}

#[test]
fn test_cross_compat_timestamp_to_unix() {
    // Timestamp 95004740 + epoch 1400000000 = Unix 1495004740
    let k = Ksuid::parse("0o5sKzFDBc56T8mbUP8wH1KpSX7").unwrap();
    assert_eq!(k.timestamp(), 95004740);
    assert_eq!(k.time(), 1495004740);
}

#[test]
fn test_cross_compat_sorting() {
    // KSUIDs should sort identically whether comparing bytes or strings
    let strings = vec![
        "aWgEPTl1tmebfsQzFP4bxwgy80V",
        "000000000000000000000000000",
        "0o5sKzFDBc56T8mbUP8wH1KpSX7",
        "IGL7CirdbzjSOihuGRwhdVqH3mh",
        "000000296tiiBb3U904RIpygpjj",
    ];
    let mut ksuids: Vec<Ksuid> = strings.iter().map(|s| Ksuid::parse(s).unwrap()).collect();
    let mut string_sorted = strings.clone();
    string_sorted.sort();

    ksuid::sort(&mut ksuids);
    let ksuid_strings: Vec<String> = ksuids.iter().map(|k| k.to_string()).collect();

    assert_eq!(
        ksuid_strings, string_sorted,
        "byte sort and string sort must match"
    );
}

#[test]
fn test_cross_compat_hex() {
    for (ts, _payload_hex, expected_str, raw_hex) in TEST_VECTORS {
        let k = Ksuid::from_hex(raw_hex).unwrap();
        assert_eq!(
            k.to_string(),
            *expected_str,
            "hex->string failed for {}",
            raw_hex
        );
        assert_eq!(k.timestamp(), *ts, "hex->timestamp failed for {}", raw_hex);
        assert_eq!(
            k.to_hex().to_lowercase(),
            raw_hex.to_lowercase(),
            "hex roundtrip failed"
        );
    }
}
