use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input string is not exactly 27 characters
    InvalidLength,
    /// Input contains a character not in the base62 alphabet
    InvalidCharacter(char),
    /// Decoded value exceeds the maximum KSUID value
    ValueOverflow,
    /// Input byte slice is not exactly 20 bytes
    InvalidBufferSize,
    /// Compressed set data is malformed
    MalformedData,
    /// Compressed set data corruption detected
    CorruptionDetected,
    /// Sequence has been exhausted (65,536 IDs generated)
    SequenceExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLength => write!(
                f,
                "invalid length: KSUID string must be exactly 27 characters"
            ),
            Error::InvalidCharacter(c) => write!(
                f,
                "invalid character: '{}' is not in the base62 alphabet",
                c
            ),
            Error::ValueOverflow => {
                write!(f, "value overflow: decoded value exceeds maximum KSUID")
            }
            Error::InvalidBufferSize => {
                write!(f, "invalid buffer size: expected exactly 20 bytes")
            }
            Error::MalformedData => write!(f, "malformed data in compressed set"),
            Error::CorruptionDetected => {
                write!(f, "corruption detected in compressed set")
            }
            Error::SequenceExhausted => {
                write!(f, "sequence exhausted: maximum 65,536 IDs per seed")
            }
        }
    }
}

impl std::error::Error for Error {}
