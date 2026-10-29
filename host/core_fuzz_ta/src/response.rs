// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Decoder for the TA's FZR2 response and per-opcode statistics.

use std::{error::Error, fmt, iter::FusedIterator, slice::ChunksExact};

use crate::protocol::{
    HEADER_COUNT_OFFSET, MAX_OPERATIONS, OPCODE_COUNT, OUTPUT_HEADER_SIZE, OUTPUT_MAGIC,
    RESULT_DATA_SIZE, RESULT_HEADER_SIZE, RESULT_SIZE, TA_VERSION, TEE_SUCCESS,
};

/// Why a response could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseError {
    /// Missing or wrong magic, version or reserved bytes.
    Header,
    /// The length does not match the declared record count.
    Length(usize),
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header => f.write_str("invalid TA response header"),
            Self::Length(length) => write!(f, "invalid TA response length: {length}"),
        }
    }
}

impl Error for ResponseError {}

/// The result record of one executed operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step<'a> {
    /// `TEE_Result` returned by the syscall, or a TA-level error.
    pub status: u32,
    /// Opcode byte copied from the input record.
    pub opcode: u8,
    /// Slot byte copied from the input record.
    pub slot: u8,
    /// Output length reported by the operation. It may exceed
    /// `RESULT_DATA_SIZE` (e.g. a SHA-512 digest or a short-buffer
    /// requirement); only the prefix is stored.
    pub reported_len: u16,
    payload: &'a [u8],
}

impl<'a> Step<'a> {
    fn from_record(record: &'a [u8]) -> Self {
        let (header, payload) = record
            .split_first_chunk::<RESULT_HEADER_SIZE>()
            .expect("chunks_exact yields complete records");
        let [s0, s1, s2, s3, opcode, slot, len_lo, len_hi] = *header;
        Self {
            status: u32::from_le_bytes([s0, s1, s2, s3]),
            opcode,
            slot,
            reported_len: u16::from_le_bytes([len_lo, len_hi]),
            payload,
        }
    }

    /// Whether the operation returned `TEE_SUCCESS`.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.status == TEE_SUCCESS
    }

    /// The stored output prefix: at most `RESULT_DATA_SIZE` bytes.
    #[must_use]
    pub fn data(&self) -> &'a [u8] {
        let stored = usize::from(self.reported_len).min(RESULT_DATA_SIZE);
        &self.payload[..stored]
    }
}

/// Iterator over the result records of a validated response.
#[derive(Clone, Debug)]
pub struct Steps<'a> {
    records: ChunksExact<'a, u8>,
}

impl<'a> Iterator for Steps<'a> {
    type Item = Step<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.records.next().map(Step::from_record)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.records.size_hint()
    }
}

impl ExactSizeIterator for Steps<'_> {}
impl FusedIterator for Steps<'_> {}

/// Validates the FZR2 header and returns the result records.
///
/// # Errors
///
/// Returns [`ResponseError`] if the magic, version, reserved bytes or length
/// do not match what the TA produces.
pub fn parse(response: &[u8]) -> Result<Steps<'_>, ResponseError> {
    let (header, records) = response
        .split_first_chunk::<OUTPUT_HEADER_SIZE>()
        .ok_or(ResponseError::Header)?;
    let [m0, m1, m2, m3, version, _, reserved0, reserved1] = *header;
    if [m0, m1, m2, m3] != OUTPUT_MAGIC || version != TA_VERSION || reserved0 != 0 || reserved1 != 0
    {
        return Err(ResponseError::Header);
    }
    let count = usize::from(header[HEADER_COUNT_OFFSET]);
    if count > MAX_OPERATIONS || records.len() != count * RESULT_SIZE {
        return Err(ResponseError::Length(response.len()));
    }
    Ok(Steps {
        records: records.chunks_exact(RESULT_SIZE),
    })
}

/// Call and success counts for one opcode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpcodeCount {
    /// Records seen with this opcode.
    pub calls: u64,
    /// Records with this opcode that returned `TEE_SUCCESS`.
    pub successes: u64,
}

/// Per-opcode counters for the defined opcodes `1..=OPCODE_COUNT`.
#[derive(Clone, Debug)]
pub struct OpcodeStats {
    /// Index 0 is unused so that the opcode is the index.
    counts: [OpcodeCount; OPCODE_COUNT + 1],
}

impl Default for OpcodeStats {
    fn default() -> Self {
        Self {
            counts: [OpcodeCount::default(); OPCODE_COUNT + 1],
        }
    }
}

impl OpcodeStats {
    /// Counts `step` and returns the updated totals for its opcode, or
    /// `None` if the opcode is not a defined one.
    pub fn record(&mut self, step: &Step<'_>) -> Option<OpcodeCount> {
        let index = usize::from(step.opcode);
        if index == 0 {
            return None;
        }
        let count = self.counts.get_mut(index)?;
        count.calls += 1;
        if step.succeeded() {
            count.successes += 1;
        }
        Some(*count)
    }

    /// Returns the totals for `opcode`, or `None` if it is not defined.
    #[must_use]
    pub fn get(&self, opcode: u8) -> Option<OpcodeCount> {
        match opcode {
            0 => None,
            _ => self.counts.get(usize::from(opcode)).copied(),
        }
    }

    /// Iterates over `(opcode, totals)` for every defined opcode.
    pub fn iter(&self) -> impl Iterator<Item = (usize, OpcodeCount)> + '_ {
        self.counts.iter().copied().enumerate().skip(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{OP_FINAL, OP_RANDOM};

    fn response(records: &[(u32, u8, u16)]) -> Vec<u8> {
        let mut bytes = vec![0; OUTPUT_HEADER_SIZE + records.len() * RESULT_SIZE];
        bytes[..4].copy_from_slice(&OUTPUT_MAGIC);
        bytes[4] = TA_VERSION;
        bytes[HEADER_COUNT_OFFSET] = u8::try_from(records.len()).unwrap();
        for (index, (status, opcode, length)) in records.iter().enumerate() {
            let record = &mut bytes[OUTPUT_HEADER_SIZE + index * RESULT_SIZE..][..RESULT_SIZE];
            record[..4].copy_from_slice(&status.to_le_bytes());
            record[4] = *opcode;
            record[6..8].copy_from_slice(&length.to_le_bytes());
            for (offset, byte) in record[RESULT_HEADER_SIZE..].iter_mut().enumerate() {
                *byte = u8::try_from(offset).unwrap();
            }
        }
        bytes
    }

    #[test]
    fn valid_response_records_opcode_success() {
        let mut stats = OpcodeStats::default();
        for step in parse(&response(&[(TEE_SUCCESS, OP_RANDOM, 32)])).unwrap() {
            assert_eq!(
                stats.record(&step),
                Some(OpcodeCount {
                    calls: 1,
                    successes: 1
                })
            );
        }
        assert_eq!(
            stats.get(OP_RANDOM),
            Some(OpcodeCount {
                calls: 1,
                successes: 1
            })
        );
        assert_eq!(stats.iter().count(), OPCODE_COUNT);
    }

    #[test]
    fn failed_and_undefined_opcodes_are_counted_correctly() {
        let mut stats = OpcodeStats::default();
        let bytes = response(&[
            (0xffff_0010, OP_FINAL, 32),
            (TEE_SUCCESS, 0, 0),
            (TEE_SUCCESS, 200, 0),
        ]);
        let recorded: Vec<_> = parse(&bytes)
            .unwrap()
            .map(|step| stats.record(&step))
            .collect();
        assert_eq!(
            recorded,
            [
                Some(OpcodeCount {
                    calls: 1,
                    successes: 0
                }),
                None,
                None
            ]
        );
    }

    #[test]
    fn long_outputs_report_the_full_length_and_keep_a_prefix() {
        let bytes = response(&[(TEE_SUCCESS, OP_FINAL, 64), (TEE_SUCCESS, OP_RANDOM, 5)]);
        let steps: Vec<_> = parse(&bytes).unwrap().collect();
        assert_eq!(steps[0].reported_len, 64);
        assert_eq!(steps[0].data().len(), RESULT_DATA_SIZE);
        assert_eq!(steps[1].data(), [0, 1, 2, 3, 4]);
    }

    #[test]
    fn malformed_responses_are_rejected() {
        let good = response(&[(TEE_SUCCESS, OP_RANDOM, 0)]);

        let mut bad_magic = good.clone();
        bad_magic[0] ^= 1;
        assert_eq!(parse(&bad_magic).err(), Some(ResponseError::Header));

        let mut bad_reserved = good.clone();
        bad_reserved[7] = 1;
        assert_eq!(parse(&bad_reserved).err(), Some(ResponseError::Header));

        assert_eq!(
            parse(&good[..OUTPUT_HEADER_SIZE]).err(),
            Some(ResponseError::Length(OUTPUT_HEADER_SIZE))
        );
        assert_eq!(parse(&good[..4]).err(), Some(ResponseError::Header));

        let too_many = response(&vec![(TEE_SUCCESS, OP_RANDOM, 0); MAX_OPERATIONS + 1]);
        assert!(matches!(parse(&too_many), Err(ResponseError::Length(_))));
    }
}
