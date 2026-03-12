use crate::{Error, Ksuid};

const RAW_KSUID: u8 = 0x00;
const TIME_DELTA: u8 = 0x40; // 1 << 6
const PAYLOAD_DELTA: u8 = 0x80; // 1 << 7
const PAYLOAD_RANGE: u8 = 0xC0; // (1 << 6) | (1 << 7)
const TAG_MASK: u8 = 0xC0;
const VALUE_MASK: u8 = 0x3F;

/// A compressed set of KSUIDs using delta encoding.
///
/// KSUIDs are sorted and stored as deltas from the previous value,
/// using varint encoding for compact representation.
pub struct CompressedSet {
    data: Vec<u8>,
}

impl CompressedSet {
    /// Compress a slice of KSUIDs into a CompressedSet.
    ///
    /// The input is sorted and deduplicated automatically.
    pub fn compress(ids: &[Ksuid]) -> Self {
        if ids.is_empty() {
            return Self { data: Vec::new() };
        }

        // Sort and deduplicate
        let mut sorted: Vec<Ksuid> = ids.to_vec();
        sorted.sort();
        sorted.dedup();

        let mut data = Vec::new();

        // Write first KSUID as raw
        data.push(RAW_KSUID);
        data.extend_from_slice(sorted[0].bytes());

        // Write subsequent KSUIDs as deltas
        for i in 1..sorted.len() {
            let prev = &sorted[i - 1];
            let curr = &sorted[i];

            let prev_ts = prev.timestamp();
            let curr_ts = curr.timestamp();

            if prev_ts == curr_ts {
                // Same timestamp -- check if payload is a simple increment
                let prev_payload_tail = u64::from_be_bytes([
                    prev.bytes()[12],
                    prev.bytes()[13],
                    prev.bytes()[14],
                    prev.bytes()[15],
                    prev.bytes()[16],
                    prev.bytes()[17],
                    prev.bytes()[18],
                    prev.bytes()[19],
                ]);
                let curr_payload_tail = u64::from_be_bytes([
                    curr.bytes()[12],
                    curr.bytes()[13],
                    curr.bytes()[14],
                    curr.bytes()[15],
                    curr.bytes()[16],
                    curr.bytes()[17],
                    curr.bytes()[18],
                    curr.bytes()[19],
                ]);
                let prefix_same = prev.bytes()[4..12] == curr.bytes()[4..12];

                if prefix_same && curr_payload_tail >= prev_payload_tail {
                    let delta = curr_payload_tail - prev_payload_tail;
                    if delta <= 0x3F && delta > 0 {
                        // PAYLOAD_RANGE: very small delta, fits in tag byte
                        data.push(PAYLOAD_RANGE | (delta as u8));
                    } else {
                        // PAYLOAD_DELTA: encode delta as varint
                        data.push(PAYLOAD_DELTA);
                        encode_varint(&mut data, delta);
                    }
                } else {
                    // Payloads differ in prefix -- store as raw
                    data.push(RAW_KSUID);
                    data.extend_from_slice(curr.bytes());
                }
            } else if curr_ts > prev_ts {
                let ts_delta = (curr_ts - prev_ts) as u64;
                // TIME_DELTA: timestamp changed
                data.push(TIME_DELTA);
                encode_varint(&mut data, ts_delta);
                // Write full payload (16 bytes)
                data.extend_from_slice(&curr.bytes()[4..20]);
            } else {
                // Should not happen after sorting, but handle gracefully
                data.push(RAW_KSUID);
                data.extend_from_slice(curr.bytes());
            }
        }

        Self { data }
    }

    /// Decompress a CompressedSet from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        // Validate by iterating through
        let set = Self {
            data: data.to_vec(),
        };
        // Try to iterate to validate
        let mut iter = set.iter();
        while iter.next_id()?.is_some() {}
        Ok(Self {
            data: data.to_vec(),
        })
    }

    /// Returns the raw compressed bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Decompress all KSUIDs into a Vec.
    pub fn to_vec(&self) -> Result<Vec<Ksuid>, Error> {
        let mut result = Vec::new();
        let mut iter = self.iter();
        while let Some(id) = iter.next_id()? {
            result.push(id);
        }
        Ok(result)
    }

    /// Returns an iterator over the compressed KSUIDs.
    pub fn iter(&self) -> CompressedSetIter<'_> {
        CompressedSetIter {
            data: &self.data,
            pos: 0,
            prev: None,
        }
    }

    /// Returns true if the compressed set is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the length of the compressed data in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

/// Iterator over a CompressedSet.
pub struct CompressedSetIter<'a> {
    data: &'a [u8],
    pos: usize,
    prev: Option<Ksuid>,
}

impl<'a> CompressedSetIter<'a> {
    /// Get the next KSUID from the compressed set.
    pub fn next_id(&mut self) -> Result<Option<Ksuid>, Error> {
        if self.pos >= self.data.len() {
            return Ok(None);
        }

        let tag_byte = self.data[self.pos];
        let tag = tag_byte & TAG_MASK;
        self.pos += 1;

        let ksuid = match tag {
            RAW_KSUID => {
                if self.pos + 20 > self.data.len() {
                    return Err(Error::CorruptionDetected);
                }
                let mut bytes = [0u8; 20];
                bytes.copy_from_slice(&self.data[self.pos..self.pos + 20]);
                self.pos += 20;
                Ksuid::from_bytes(&bytes)
            }
            TIME_DELTA => {
                let prev = self.prev.ok_or(Error::CorruptionDetected)?;
                let (delta, consumed) =
                    decode_varint(&self.data[self.pos..]).ok_or(Error::CorruptionDetected)?;
                self.pos += consumed;

                if self.pos + 16 > self.data.len() {
                    return Err(Error::CorruptionDetected);
                }

                let new_ts = prev.timestamp().wrapping_add(delta as u32);
                let mut payload = [0u8; 16];
                payload.copy_from_slice(&self.data[self.pos..self.pos + 16]);
                self.pos += 16;

                Ksuid::from_parts(new_ts, &payload)
            }
            PAYLOAD_DELTA => {
                let prev = self.prev.ok_or(Error::CorruptionDetected)?;
                let (delta, consumed) =
                    decode_varint(&self.data[self.pos..]).ok_or(Error::CorruptionDetected)?;
                self.pos += consumed;

                let mut bytes = *prev.bytes();
                // Add delta to last 8 bytes of payload
                let tail = u64::from_be_bytes([
                    bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18],
                    bytes[19],
                ]);
                let new_tail = tail.wrapping_add(delta);
                let new_tail_bytes = new_tail.to_be_bytes();
                bytes[12..20].copy_from_slice(&new_tail_bytes);

                Ksuid::from_bytes(&bytes)
            }
            PAYLOAD_RANGE => {
                let prev = self.prev.ok_or(Error::CorruptionDetected)?;
                let delta = (tag_byte & VALUE_MASK) as u64;
                if delta == 0 {
                    return Err(Error::CorruptionDetected);
                }

                let mut bytes = *prev.bytes();
                let tail = u64::from_be_bytes([
                    bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18],
                    bytes[19],
                ]);
                let new_tail = tail.wrapping_add(delta);
                let new_tail_bytes = new_tail.to_be_bytes();
                bytes[12..20].copy_from_slice(&new_tail_bytes);

                Ksuid::from_bytes(&bytes)
            }
            _ => return Err(Error::MalformedData),
        };

        self.prev = Some(ksuid);
        Ok(Some(ksuid))
    }
}

fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}
