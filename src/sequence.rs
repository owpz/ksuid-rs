use crate::{Error, Ksuid};

/// Monotonic KSUID generator that increments the payload for sequential IDs.
///
/// Generates up to 65,536 ordered KSUIDs from a single seed. The sequence
/// writes a 16-bit counter into the last 2 bytes of the payload.
pub struct Sequence {
    seed: Ksuid,
    counter: u32,
}

impl Sequence {
    /// Create a new Sequence seeded with a fresh KSUID.
    pub fn new() -> Self {
        Self {
            seed: Ksuid::new(),
            counter: 0,
        }
    }

    /// Create a new Sequence from a specific seed KSUID.
    pub fn from_seed(seed: Ksuid) -> Self {
        Self { seed, counter: 0 }
    }

    /// Generate the next KSUID in the sequence.
    ///
    /// Returns `Err(Error::SequenceExhausted)` if 65,536 IDs have been generated.
    /// Use `reseed()` to start a new sequence.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Ksuid, Error> {
        if self.counter >= 65_536 {
            return Err(Error::SequenceExhausted);
        }

        let mut bytes = *self.seed.bytes();
        // Add counter to the last 2 payload bytes (index 18-19) as a big-endian u16
        let base = u16::from_be_bytes([bytes[18], bytes[19]]);
        let sum = base.wrapping_add(self.counter as u16);
        let sum_bytes = sum.to_be_bytes();
        bytes[18] = sum_bytes[0];
        bytes[19] = sum_bytes[1];

        self.counter += 1;
        Ok(Ksuid::from_bytes(&bytes))
    }

    /// Returns the number of IDs generated so far.
    pub fn count(&self) -> u32 {
        self.counter
    }

    /// Returns true if the sequence has been exhausted (65,536 IDs generated).
    pub fn is_exhausted(&self) -> bool {
        self.counter >= 65_536
    }

    /// Reset the counter to 0 with a new random seed.
    pub fn reseed(&mut self) {
        self.seed = Ksuid::new();
        self.counter = 0;
    }

    /// Reset the counter to 0 with a specific seed.
    pub fn reseed_with(&mut self, seed: Ksuid) {
        self.seed = seed;
        self.counter = 0;
    }

    /// Returns the seed KSUID.
    pub fn seed(&self) -> Ksuid {
        self.seed
    }

    /// Returns the bounds (min, max) of the remaining sequence values.
    pub fn bounds(&self) -> (Ksuid, Ksuid) {
        let min = if self.counter < 65_536 {
            let mut bytes = *self.seed.bytes();
            let base = u16::from_be_bytes([bytes[18], bytes[19]]);
            let sum = base.wrapping_add(self.counter as u16);
            let sum_bytes = sum.to_be_bytes();
            bytes[18] = sum_bytes[0];
            bytes[19] = sum_bytes[1];
            Ksuid::from_bytes(&bytes)
        } else {
            self.seed
        };

        let max = {
            let mut bytes = *self.seed.bytes();
            let base = u16::from_be_bytes([bytes[18], bytes[19]]);
            let sum = base.wrapping_add(0xFFFFu16);
            let sum_bytes = sum.to_be_bytes();
            bytes[18] = sum_bytes[0];
            bytes[19] = sum_bytes[1];
            Ksuid::from_bytes(&bytes)
        };

        (min, max)
    }
}

impl Default for Sequence {
    fn default() -> Self {
        Self::new()
    }
}
