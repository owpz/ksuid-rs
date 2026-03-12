/// The base62 alphabet used for KSUID encoding.
pub const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Length of an encoded KSUID string.
pub const ENCODED_LEN: usize = 27;

/// Length of a decoded KSUID in bytes.
pub const DECODED_LEN: usize = 20;

/// Reverse lookup table: ASCII byte -> base62 digit value (255 = invalid)
const DECODE_MAP: [u8; 128] = {
    let mut map = [255u8; 128];
    let mut i = 0;
    while i < 62 {
        map[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    map
};

pub fn encode(src: &[u8; 20]) -> [u8; 27] {
    // Load 20 bytes as 5 x u32 big-endian words
    let mut words = [0u32; 5];
    words[0] = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    words[1] = u32::from_be_bytes([src[4], src[5], src[6], src[7]]);
    words[2] = u32::from_be_bytes([src[8], src[9], src[10], src[11]]);
    words[3] = u32::from_be_bytes([src[12], src[13], src[14], src[15]]);
    words[4] = u32::from_be_bytes([src[16], src[17], src[18], src[19]]);

    let mut dst = [b'0'; 27]; // Pre-fill with '0' for padding

    // Extract base62 digits from right to left
    let mut i = 26i32;
    while i >= 0 {
        let mut carry = 0u64;
        for word in words.iter_mut() {
            let value = carry * (1u64 << 32) + *word as u64;
            *word = (value / 62) as u32;
            carry = value % 62;
        }
        dst[i as usize] = ALPHABET[carry as usize];
        i -= 1;
    }
    dst
}

pub fn decode(src: &[u8; 27]) -> Result<[u8; 20], crate::Error> {
    // Convert base62 chars to digit values
    let mut digits = [0u8; 27];
    for (i, &b) in src.iter().enumerate() {
        if b >= 128 {
            return Err(crate::Error::InvalidCharacter(b as char));
        }
        let d = DECODE_MAP[b as usize];
        if d == 255 {
            return Err(crate::Error::InvalidCharacter(b as char));
        }
        digits[i] = d;
    }

    let mut dst = [0u8; 20];

    // Extract u32 words from right to left
    let mut word_idx = 4i32;
    while word_idx >= 0 {
        let mut carry = 0u64;
        for digit in digits.iter_mut() {
            let value = carry * 62 + *digit as u64;
            *digit = (value / (1u64 << 32)) as u8;
            carry = value % (1u64 << 32);
        }
        let offset = (word_idx as usize) * 4;
        let bytes = (carry as u32).to_be_bytes();
        dst[offset] = bytes[0];
        dst[offset + 1] = bytes[1];
        dst[offset + 2] = bytes[2];
        dst[offset + 3] = bytes[3];
        word_idx -= 1;
    }

    // Check for overflow: all digits should be zero after extraction
    for &d in &digits {
        if d != 0 {
            return Err(crate::Error::ValueOverflow);
        }
    }

    Ok(dst)
}
