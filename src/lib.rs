pub mod base62;
mod compressed_set;
mod error;
mod sequence;
mod sort;

pub use compressed_set::{CompressedSet, CompressedSetIter};
pub use error::Error;
pub use sequence::Sequence;
pub use sort::{compare, is_sorted, sort};

use core::fmt;
use core::str::FromStr;

/// KSUID epoch: May 13, 2014 in Unix seconds
const EPOCH: u64 = 1_400_000_000;

/// Size of a KSUID in bytes
const BYTE_SIZE: usize = 20;

/// Size of the payload in bytes
const PAYLOAD_SIZE: usize = 16;

/// Size of the encoded string
const ENCODED_SIZE: usize = 27;

/// A K-Sortable Unique Identifier.
///
/// KSUIDs are 20-byte identifiers that are time-sortable. The first 4 bytes
/// are a timestamp (seconds since the KSUID epoch), and the remaining 16 bytes
/// are cryptographically random.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct Ksuid([u8; BYTE_SIZE]);

impl Ksuid {
    /// The nil KSUID (all zeros).
    pub const NIL: Ksuid = Ksuid([0u8; BYTE_SIZE]);

    /// The maximum KSUID (all 0xFF).
    pub const MAX: Ksuid = Ksuid([0xFF; BYTE_SIZE]);

    /// Generate a new KSUID with the current time and a random payload.
    pub fn new() -> Self {
        let timestamp = current_timestamp();
        Self::new_with_time(timestamp)
    }

    /// Generate a new KSUID with the given Unix timestamp and a random payload.
    pub fn new_with_time(unix_seconds: u64) -> Self {
        let ts = unix_seconds.saturating_sub(EPOCH) as u32;
        let mut payload = [0u8; PAYLOAD_SIZE];
        getrandom::getrandom(&mut payload).expect("getrandom failed");
        Self::from_parts(ts, &payload)
    }

    /// Construct a KSUID from a timestamp and payload.
    pub fn from_parts(timestamp: u32, payload: &[u8; PAYLOAD_SIZE]) -> Self {
        let mut bytes = [0u8; BYTE_SIZE];
        let ts_bytes = timestamp.to_be_bytes();
        bytes[0] = ts_bytes[0];
        bytes[1] = ts_bytes[1];
        bytes[2] = ts_bytes[2];
        bytes[3] = ts_bytes[3];
        bytes[4..].copy_from_slice(payload);
        Ksuid(bytes)
    }

    /// Construct a KSUID from raw bytes.
    pub fn from_bytes(bytes: &[u8; BYTE_SIZE]) -> Self {
        Ksuid(*bytes)
    }

    /// Construct a KSUID from a byte slice.
    /// Returns an error if the slice is not exactly 20 bytes.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: &[u8; 20] = bytes.try_into().map_err(|_| Error::InvalidBufferSize)?;
        Ok(Ksuid(*arr))
    }

    /// Construct a KSUID from a byte slice, returning NIL if invalid.
    pub fn from_bytes_or_nil(bytes: &[u8]) -> Self {
        Self::try_from_bytes(bytes).unwrap_or(Self::NIL)
    }

    /// Construct a KSUID from parts, returning NIL if payload length is wrong.
    pub fn from_parts_or_nil(timestamp: u32, payload: &[u8]) -> Self {
        if payload.len() != PAYLOAD_SIZE {
            return Self::NIL;
        }
        let p: &[u8; PAYLOAD_SIZE] = payload.try_into().unwrap();
        Self::from_parts(timestamp, p)
    }

    /// Parse a KSUID from a 27-character base62 string.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let bytes = s.as_bytes();
        if bytes.len() != ENCODED_SIZE {
            return Err(Error::InvalidLength);
        }
        let src: &[u8; 27] = bytes.try_into().unwrap();
        let decoded = base62::decode(src)?;
        Ok(Ksuid(decoded))
    }

    /// Parse a KSUID from a string, returning NIL on error.
    pub fn parse_or_nil(s: &str) -> Self {
        Self::parse(s).unwrap_or(Self::NIL)
    }

    /// The raw timestamp (seconds since KSUID epoch).
    pub fn timestamp(&self) -> u32 {
        u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    /// The Unix timestamp.
    pub fn time(&self) -> u64 {
        self.timestamp() as u64 + EPOCH
    }

    /// The 16-byte payload.
    pub fn payload(&self) -> &[u8; PAYLOAD_SIZE] {
        self.0[4..].try_into().unwrap()
    }

    /// The full 20-byte value.
    pub fn bytes(&self) -> &[u8; BYTE_SIZE] {
        &self.0
    }

    /// Returns true if this is the nil KSUID (all zeros).
    pub fn is_nil(&self) -> bool {
        self.0 == [0u8; BYTE_SIZE]
    }

    /// Compare this KSUID with another, returning an i32.
    ///
    /// Returns -1 if self < other, 0 if equal, 1 if self > other.
    /// Provided for API compatibility with the TypeScript implementation.
    pub fn compare(&self, other: &Self) -> i32 {
        match self.cmp(other) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        }
    }

    /// Returns the next KSUID by incrementing the entire 20-byte value by 1.
    /// Wraps from MAX to NIL.
    pub fn next(&self) -> Self {
        let mut bytes = self.0;
        let mut i = BYTE_SIZE - 1;
        loop {
            let (val, overflow) = bytes[i].overflowing_add(1);
            bytes[i] = val;
            if !overflow || i == 0 {
                break;
            }
            i -= 1;
        }
        Ksuid(bytes)
    }

    /// Returns the previous KSUID by decrementing the entire 20-byte value by 1.
    /// Wraps from NIL to MAX.
    pub fn prev(&self) -> Self {
        let mut bytes = self.0;
        let mut i = BYTE_SIZE - 1;
        loop {
            let (val, overflow) = bytes[i].overflowing_sub(1);
            bytes[i] = val;
            if !overflow || i == 0 {
                break;
            }
            i -= 1;
        }
        Ksuid(bytes)
    }

    /// Encode the KSUID as a 40-character uppercase hex string.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for &b in &self.0 {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0F) as usize] as char);
        }
        s
    }

    /// Parse a KSUID from a 40-character hex string.
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let hex = hex.as_bytes();
        if hex.len() != 40 {
            return Err(Error::InvalidLength);
        }
        let mut bytes = [0u8; 20];
        for i in 0..20 {
            let hi = hex_digit(hex[i * 2])?;
            let lo = hex_digit(hex[i * 2 + 1])?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Ksuid(bytes))
    }
}

const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

fn hex_digit(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(Error::InvalidCharacter(c as char)),
    }
}

impl Default for Ksuid {
    fn default() -> Self {
        Self::NIL
    }
}

impl Ord for Ksuid {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for Ksuid {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Ksuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = base62::encode(&self.0);
        // Safety: base62::encode only produces ASCII characters from ALPHABET
        let s = core::str::from_utf8(&encoded).unwrap();
        f.write_str(s)
    }
}

impl fmt::Debug for Ksuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ksuid({})", self)
    }
}

impl FromStr for Ksuid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<[u8]> for Ksuid {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for Ksuid {
    fn from(bytes: [u8; 20]) -> Self {
        Ksuid(bytes)
    }
}

impl From<Ksuid> for [u8; 20] {
    fn from(k: Ksuid) -> Self {
        k.0
    }
}

// Serde support behind feature flag
#[cfg(feature = "serde")]
impl serde::Serialize for Ksuid {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            let encoded = base62::encode(&self.0);
            let s = core::str::from_utf8(&encoded).unwrap();
            serializer.serialize_str(s)
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Ksuid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = <&str>::deserialize(deserializer)?;
            Ksuid::parse(s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            if bytes.len() != BYTE_SIZE {
                return Err(serde::de::Error::custom("expected 20 bytes"));
            }
            let arr: [u8; BYTE_SIZE] = bytes.try_into().unwrap();
            Ok(Ksuid(arr))
        }
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nil_constant() {
        assert_eq!(Ksuid::NIL.to_string(), "000000000000000000000000000");
        assert!(Ksuid::NIL.is_nil());
    }

    #[test]
    fn test_max_constant() {
        assert_eq!(Ksuid::MAX.to_string(), "aWgEPTl1tmebfsQzFP4bxwgy80V");
        assert!(!Ksuid::MAX.is_nil());
    }

    #[test]
    fn test_default_is_nil() {
        assert_eq!(Ksuid::default(), Ksuid::NIL);
    }

    #[test]
    fn test_parse_nil() {
        let parsed = Ksuid::parse("000000000000000000000000000").unwrap();
        assert_eq!(parsed, Ksuid::NIL);
    }

    #[test]
    fn test_parse_max() {
        let parsed = Ksuid::parse("aWgEPTl1tmebfsQzFP4bxwgy80V").unwrap();
        assert_eq!(parsed, Ksuid::MAX);
    }

    #[test]
    fn test_roundtrip_nil() {
        let s = Ksuid::NIL.to_string();
        let parsed = Ksuid::parse(&s).unwrap();
        assert_eq!(parsed, Ksuid::NIL);
    }

    #[test]
    fn test_roundtrip_max() {
        let s = Ksuid::MAX.to_string();
        let parsed = Ksuid::parse(&s).unwrap();
        assert_eq!(parsed, Ksuid::MAX);
    }

    #[test]
    fn test_known_ksuid_roundtrip_1() {
        let s = "0ujsszwN8NRY24YaXiTIE2VWDTS";
        let parsed = Ksuid::parse(s).unwrap();
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn test_known_ksuid_roundtrip_2() {
        let s = "0ujtsYcgvSTl8PAuAdqWYSMnLOv";
        let parsed = Ksuid::parse(s).unwrap();
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn test_parse_invalid_length() {
        assert!(Ksuid::parse("too_short").is_err());
        assert!(Ksuid::parse("").is_err());
    }

    #[test]
    fn test_parse_invalid_character() {
        // 27 chars but with invalid character
        assert!(Ksuid::parse("000000000000000000000000 00").is_err());
    }

    #[test]
    fn test_parse_or_nil_invalid() {
        assert_eq!(Ksuid::parse_or_nil("invalid"), Ksuid::NIL);
    }

    #[test]
    fn test_from_parts() {
        let ts: u32 = 123456;
        let payload = [1u8; 16];
        let k = Ksuid::from_parts(ts, &payload);
        assert_eq!(k.timestamp(), ts);
        assert_eq!(k.payload(), &payload);
    }

    #[test]
    fn test_from_bytes() {
        let mut bytes = [0u8; 20];
        bytes[0] = 0x01;
        bytes[19] = 0xFF;
        let k = Ksuid::from_bytes(&bytes);
        assert_eq!(k.bytes(), &bytes);
    }

    #[test]
    fn test_time() {
        let ts: u32 = 100;
        let payload = [0u8; 16];
        let k = Ksuid::from_parts(ts, &payload);
        assert_eq!(k.time(), 100 + 1_400_000_000);
    }

    #[test]
    fn test_ordering() {
        let k1 = Ksuid::from_parts(100, &[0u8; 16]);
        let k2 = Ksuid::from_parts(200, &[0u8; 16]);
        assert!(k1 < k2);
    }

    #[test]
    fn test_ordering_consistent_with_string() {
        // Verify byte ordering and string ordering are consistent
        let k1 = Ksuid::from_parts(100, &[0u8; 16]);
        let k2 = Ksuid::from_parts(200, &[0u8; 16]);
        let s1 = k1.to_string();
        let s2 = k2.to_string();
        assert_eq!(k1.cmp(&k2), s1.cmp(&s2));
    }

    #[test]
    fn test_next() {
        let k = Ksuid::from_parts(100, &[0u8; 16]);
        let n = k.next();
        assert_eq!(n.timestamp(), 100);
        assert_eq!(n.payload()[15], 1);
        assert!(n > k);
    }

    #[test]
    fn test_prev() {
        let k = Ksuid::from_parts(100, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let p = k.prev();
        assert_eq!(p.timestamp(), 100);
        assert_eq!(p.payload(), &[0u8; 16]);
        assert!(p < k);
    }

    #[test]
    fn test_next_overflow() {
        // Payload is all 0xFF, next() now increments full 20 bytes so timestamp increments
        let k = Ksuid::from_parts(100, &[0xFF; 16]);
        let n = k.next();
        assert_eq!(n, Ksuid::from_parts(101, &[0u8; 16]));
    }

    #[test]
    fn test_prev_underflow() {
        // Payload is all 0x00, prev() now decrements full 20 bytes so timestamp decrements
        let k = Ksuid::from_parts(100, &[0u8; 16]);
        let p = k.prev();
        assert_eq!(p, Ksuid::from_parts(99, &[0xFF; 16]));
    }

    #[test]
    fn test_next_wraps_max_to_nil() {
        assert_eq!(Ksuid::MAX.next(), Ksuid::NIL);
    }

    #[test]
    fn test_prev_wraps_nil_to_max() {
        assert_eq!(Ksuid::NIL.prev(), Ksuid::MAX);
    }

    #[test]
    fn test_new_generates_unique() {
        let k1 = Ksuid::new();
        let k2 = Ksuid::new();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_new_is_not_nil() {
        let k = Ksuid::new();
        assert!(!k.is_nil());
    }

    #[test]
    fn test_display_length() {
        let k = Ksuid::new();
        assert_eq!(k.to_string().len(), 27);
    }

    #[test]
    fn test_from_str() {
        let s = "0ujsszwN8NRY24YaXiTIE2VWDTS";
        let k: Ksuid = s.parse().unwrap();
        assert_eq!(k.to_string(), s);
    }

    #[test]
    fn test_debug() {
        let k = Ksuid::NIL;
        let debug = format!("{:?}", k);
        assert!(debug.starts_with("Ksuid("));
    }

    #[test]
    fn test_sequence_monotonic() {
        let mut seq = Sequence::new();
        let mut prev = seq.next().unwrap();
        for _ in 0..100 {
            let curr = seq.next().unwrap();
            assert!(curr > prev, "sequence must be monotonically increasing");
            prev = curr;
        }
    }

    #[test]
    fn test_roundtrip_random() {
        // Generate random KSUIDs and verify encode/decode roundtrip
        for _ in 0..100 {
            let k = Ksuid::new();
            let s = k.to_string();
            assert_eq!(s.len(), 27);
            let parsed = Ksuid::parse(&s).unwrap();
            assert_eq!(k, parsed);
        }
    }

    #[test]
    fn test_base62_encode_decode_roundtrip_all_bytes() {
        // Test with various byte patterns
        let patterns: Vec<[u8; 20]> = vec![
            [0u8; 20],
            [0xFF; 20],
            [0x80; 20],
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            ],
        ];
        for bytes in patterns {
            let encoded = base62::encode(&bytes);
            let decoded = base62::decode(&encoded).unwrap();
            assert_eq!(bytes, decoded, "roundtrip failed for {:?}", bytes);
        }
    }

    #[test]
    fn test_known_ksuid_bytes() {
        // Test vector: "0ujsszwN8NRY24YaXiTIE2VWDTS"
        // This should decode to specific bytes and re-encode to the same string
        let s = "0ujsszwN8NRY24YaXiTIE2VWDTS";
        let k = Ksuid::parse(s).unwrap();
        let re_encoded = k.to_string();
        assert_eq!(re_encoded, s);

        // Verify timestamp is reasonable (not zero, not max)
        assert!(k.timestamp() > 0);
        assert!(k.timestamp() < u32::MAX);
    }

    #[test]
    fn test_overflow_detection() {
        // A string that would decode to more than 20 bytes should be caught
        // "aWgEPTl1tmebfsQzFP4bxwgy80V" is MAX (all 0xFF) - valid
        // Anything "larger" in base62 should overflow
        // The character after 'V' in base62 at position 26 would be 'W'
        let overflow = "aWgEPTl1tmebfsQzFP4bxwgy80W";
        assert!(Ksuid::parse(overflow).is_err());
    }

    #[test]
    fn test_as_ref() {
        let k = Ksuid::NIL;
        let bytes: &[u8] = k.as_ref();
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes, &[0u8; 20]);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let k1 = Ksuid::new();
        let k2 = Ksuid::new();
        set.insert(k1);
        set.insert(k2);
        assert_eq!(set.len(), 2);
        set.insert(k1);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<Ksuid>();
        assert_sync::<Ksuid>();
    }

    #[test]
    fn test_try_from_bytes() {
        let bytes = [42u8; 20];
        let k = Ksuid::try_from_bytes(&bytes).unwrap();
        assert_eq!(k.bytes(), &bytes);

        // Wrong length should fail
        assert!(Ksuid::try_from_bytes(&[0u8; 19]).is_err());
        assert!(Ksuid::try_from_bytes(&[0u8; 21]).is_err());
    }

    #[test]
    fn test_from_bytes_or_nil() {
        let bytes = [42u8; 20];
        let k = Ksuid::from_bytes_or_nil(&bytes);
        assert_eq!(k.bytes(), &bytes);

        let k = Ksuid::from_bytes_or_nil(&[0u8; 5]);
        assert_eq!(k, Ksuid::NIL);
    }

    #[test]
    fn test_from_parts_or_nil() {
        let k = Ksuid::from_parts_or_nil(100, &[1u8; 16]);
        assert_eq!(k.timestamp(), 100);

        let k = Ksuid::from_parts_or_nil(100, &[1u8; 15]);
        assert_eq!(k, Ksuid::NIL);
    }

    #[test]
    fn test_compare_method() {
        let k1 = Ksuid::from_parts(100, &[0u8; 16]);
        let k2 = Ksuid::from_parts(200, &[0u8; 16]);
        assert_eq!(k1.compare(&k2), -1);
        assert_eq!(k2.compare(&k1), 1);
        assert_eq!(k1.compare(&k1), 0);
    }

    #[test]
    fn test_from_into_array() {
        let bytes = [7u8; 20];
        let k: Ksuid = bytes.into();
        let back: [u8; 20] = k.into();
        assert_eq!(bytes, back);
    }

    #[test]
    fn test_sort_utilities() {
        let k1 = Ksuid::from_parts(300, &[0u8; 16]);
        let k2 = Ksuid::from_parts(100, &[0u8; 16]);
        let k3 = Ksuid::from_parts(200, &[0u8; 16]);
        let mut ids = vec![k1, k2, k3];

        assert!(!is_sorted(&ids));
        sort(&mut ids);
        assert!(is_sorted(&ids));
        assert_eq!(ids[0], k2);
        assert_eq!(ids[1], k3);
        assert_eq!(ids[2], k1);
    }

    #[test]
    fn test_compare_fn() {
        let k1 = Ksuid::from_parts(100, &[0u8; 16]);
        let k2 = Ksuid::from_parts(200, &[0u8; 16]);
        assert_eq!(compare(&k1, &k2), core::cmp::Ordering::Less);
        assert_eq!(compare(&k2, &k1), core::cmp::Ordering::Greater);
        assert_eq!(compare(&k1, &k1), core::cmp::Ordering::Equal);
    }

    #[test]
    fn test_compressed_set_roundtrip() {
        let ids: Vec<Ksuid> = (0..10)
            .map(|i| Ksuid::from_parts(100, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i]))
            .collect();

        let set = CompressedSet::compress(&ids);
        assert!(!set.is_empty());
        assert!(set.len() < 20 * 10); // Should be compressed

        let decompressed = set.to_vec().unwrap();
        assert_eq!(decompressed.len(), ids.len());

        // Verify sorted order
        let mut sorted_ids = ids.clone();
        sorted_ids.sort();
        assert_eq!(decompressed, sorted_ids);
    }

    #[test]
    fn test_compressed_set_empty() {
        let set = CompressedSet::compress(&[]);
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        let decompressed = set.to_vec().unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_compressed_set_single() {
        let k = Ksuid::from_parts(100, &[1u8; 16]);
        let set = CompressedSet::compress(&[k]);
        let decompressed = set.to_vec().unwrap();
        assert_eq!(decompressed, vec![k]);
    }

    #[test]
    fn test_compressed_set_dedup() {
        let k = Ksuid::from_parts(100, &[1u8; 16]);
        let set = CompressedSet::compress(&[k, k, k]);
        let decompressed = set.to_vec().unwrap();
        assert_eq!(decompressed, vec![k]);
    }

    #[test]
    fn test_compressed_set_time_delta() {
        let k1 = Ksuid::from_parts(100, &[1u8; 16]);
        let k2 = Ksuid::from_parts(200, &[2u8; 16]);
        let set = CompressedSet::compress(&[k1, k2]);
        let decompressed = set.to_vec().unwrap();
        assert_eq!(decompressed, vec![k1, k2]);
    }

    #[test]
    fn test_compressed_set_from_bytes_roundtrip() {
        let ids: Vec<Ksuid> = (0..5)
            .map(|i| Ksuid::from_parts(100 + i, &[i as u8; 16]))
            .collect();

        let set = CompressedSet::compress(&ids);
        let raw = set.to_bytes().to_vec();
        let set2 = CompressedSet::from_bytes(&raw).unwrap();
        let decompressed = set2.to_vec().unwrap();

        let mut sorted_ids = ids;
        sorted_ids.sort();
        assert_eq!(decompressed, sorted_ids);
    }

    #[test]
    fn test_sequence_exhaustion() {
        let seed = Ksuid::from_parts(100, &[0u8; 16]);
        let mut seq = Sequence::from_seed(seed);
        assert_eq!(seq.count(), 0);
        assert!(!seq.is_exhausted());

        // Generate all 65536 IDs
        for _ in 0..65_536 {
            seq.next().unwrap();
        }

        assert_eq!(seq.count(), 65_536);
        assert!(seq.is_exhausted());
        assert!(seq.next().is_err());
    }

    #[test]
    fn test_sequence_reseed() {
        let seed = Ksuid::from_parts(100, &[0u8; 16]);
        let mut seq = Sequence::from_seed(seed);
        seq.next().unwrap();
        assert_eq!(seq.count(), 1);

        let new_seed = Ksuid::from_parts(200, &[0u8; 16]);
        seq.reseed_with(new_seed);
        assert_eq!(seq.count(), 0);
        assert_eq!(seq.seed(), new_seed);
    }

    #[test]
    fn test_sequence_bounds() {
        let seed = Ksuid::from_parts(100, &[0u8; 16]);
        let seq = Sequence::from_seed(seed);
        let (min, max) = seq.bounds();
        assert_eq!(min, seed);
        assert!(max > min);
    }

    #[test]
    fn test_to_hex_nil() {
        assert_eq!(
            Ksuid::NIL.to_hex(),
            "0000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_to_hex_max() {
        assert_eq!(
            Ksuid::MAX.to_hex(),
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        );
    }

    #[test]
    fn test_from_hex_roundtrip() {
        let k = Ksuid::new();
        let hex = k.to_hex();
        assert_eq!(hex.len(), 40);
        let parsed = Ksuid::from_hex(&hex).unwrap();
        assert_eq!(k, parsed);
    }

    #[test]
    fn test_from_hex_lowercase() {
        let hex = "05a9a844669f7efd7b6fe812278486085878563d";
        let k = Ksuid::from_hex(hex).unwrap();
        assert_eq!(k.timestamp(), 95004740);
    }

    #[test]
    fn test_from_hex_invalid_length() {
        assert!(Ksuid::from_hex("ABCD").is_err());
    }

    #[test]
    fn test_from_hex_invalid_character() {
        assert!(Ksuid::from_hex("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG").is_err());
    }

    #[test]
    fn test_hex_cross_compat() {
        // From TypeScript test vectors
        let k = Ksuid::from_hex("05a9a844669f7efd7b6fe812278486085878563d").unwrap();
        assert_eq!(k.to_string(), "0o5sKzFDBc56T8mbUP8wH1KpSX7");
    }
}
