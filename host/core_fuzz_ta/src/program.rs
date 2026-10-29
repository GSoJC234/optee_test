// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! The FZP2 input program: an 8-byte header followed by operation records.
//!
//! The layout is documented in `ta/core_fuzz_ta/README.md`. Parsing is only
//! as strict as the TA itself, so header magic, version, reserved bytes,
//! unknown opcodes and trailing bytes are kept as fuzzable data.

use crate::protocol::{
    HEADER_COUNT_OFFSET, INPUT_HEADER_SIZE, MAX_INPUT_SIZE, MAX_OPERATIONS, OP_HEADER_SIZE,
    SLOT_COUNT,
};

/// One operation record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    /// Opcode byte; values outside `1..=MAX_OPCODE` are legal fuzz input.
    pub opcode: u8,
    /// State or object slot, `0..SLOT_COUNT`.
    pub slot: u8,
    /// Opcode-specific selector.
    pub selector: u8,
    /// Opcode-specific auxiliary value.
    pub aux: u16,
    /// Record payload; its length is encoded as a 16-bit field.
    pub data: Vec<u8>,
}

/// A decoded input program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    /// Raw input header. The operation count byte is rewritten by
    /// [`Program::encode`]; the other bytes are preserved as fuzz data.
    pub header: [u8; INPUT_HEADER_SIZE],
    /// Operation records in execution order.
    pub operations: Vec<Operation>,
    /// Bytes after the last declared record.
    pub trailing: Vec<u8>,
}

impl Program {
    /// Decodes `bytes` with the same framing checks the TA applies.
    ///
    /// Returns `None` for inputs the TA would reject with
    /// `TEE_ERROR_BAD_PARAMETERS`: oversized input, too many records, a
    /// truncated record or an out-of-range slot.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_INPUT_SIZE {
            return None;
        }
        let (header, mut rest) = bytes.split_first_chunk::<INPUT_HEADER_SIZE>()?;
        let count = usize::from(header[HEADER_COUNT_OFFSET]);
        if count > MAX_OPERATIONS {
            return None;
        }

        let mut operations = Vec::with_capacity(count);
        for _ in 0..count {
            let (record, tail) = rest.split_first_chunk::<OP_HEADER_SIZE>()?;
            let [opcode, slot, selector, len_lo, len_hi, aux_lo, aux_hi] = *record;
            if usize::from(slot) >= SLOT_COUNT {
                return None;
            }
            let data_len = usize::from(u16::from_le_bytes([len_lo, len_hi]));
            let (data, tail) = tail.split_at_checked(data_len)?;
            operations.push(Operation {
                opcode,
                slot,
                selector,
                aux: u16::from_le_bytes([aux_lo, aux_hi]),
                data: data.to_vec(),
            });
            rest = tail;
        }

        Some(Self {
            header: *header,
            operations,
            trailing: rest.to_vec(),
        })
    }

    /// Returns the encoded size, or `None` if a record cannot be encoded
    /// (payload longer than `u16::MAX` or slot out of range).
    #[must_use]
    pub fn encoded_len(&self) -> Option<usize> {
        let fixed = INPUT_HEADER_SIZE.checked_add(self.trailing.len())?;
        self.operations.iter().try_fold(fixed, |length, operation| {
            if operation.data.len() > usize::from(u16::MAX)
                || usize::from(operation.slot) >= SLOT_COUNT
            {
                return None;
            }
            length
                .checked_add(OP_HEADER_SIZE)?
                .checked_add(operation.data.len())
        })
    }

    /// Encodes the program, or returns `None` if it violates the TA limits.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.operations.len() > MAX_OPERATIONS {
            return None;
        }
        let count = u8::try_from(self.operations.len()).ok()?;
        let encoded_len = self.encoded_len()?;
        if encoded_len > MAX_INPUT_SIZE {
            return None;
        }

        let mut header = self.header;
        header[HEADER_COUNT_OFFSET] = count;
        let mut bytes = Vec::with_capacity(encoded_len);
        bytes.extend_from_slice(&header);
        for operation in &self.operations {
            let data_len = u16::try_from(operation.data.len()).ok()?;
            bytes.extend_from_slice(&[operation.opcode, operation.slot, operation.selector]);
            bytes.extend_from_slice(&data_len.to_le_bytes());
            bytes.extend_from_slice(&operation.aux.to_le_bytes());
            bytes.extend_from_slice(&operation.data);
        }
        bytes.extend_from_slice(&self.trailing);
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{INPUT_MAGIC, OP_RANDOM, TA_VERSION};

    fn operation(data: Vec<u8>) -> Operation {
        Operation {
            opcode: OP_RANDOM,
            slot: 0,
            selector: 0,
            aux: 12,
            data,
        }
    }

    fn sample_program() -> Program {
        let mut header = [0; INPUT_HEADER_SIZE];
        header[..4].copy_from_slice(&INPUT_MAGIC);
        header[4] = TA_VERSION;
        header[HEADER_COUNT_OFFSET] = 1;
        Program {
            header,
            operations: vec![operation(vec![0xaa, 0xbb])],
            trailing: vec![0x55],
        }
    }

    #[test]
    fn encode_parse_round_trip_preserves_records_and_trailing_bytes() {
        let program = sample_program();
        let encoded = program.encode().unwrap();
        assert_eq!(&encoded[..8], b"FZP2\x02\x01\0\0");
        assert_eq!(Program::parse(&encoded), Some(program));
    }

    #[test]
    fn parser_rejects_truncated_records_bad_slots_and_oversized_inputs() {
        let encoded = sample_program().encode().unwrap();
        assert!(Program::parse(&encoded[..INPUT_HEADER_SIZE - 1]).is_none());
        assert!(Program::parse(&encoded[..encoded.len() - 2]).is_none());

        let mut bad_slot = encoded.clone();
        bad_slot[INPUT_HEADER_SIZE + 1] = u8::try_from(SLOT_COUNT).unwrap();
        assert!(Program::parse(&bad_slot).is_none());

        assert!(Program::parse(&vec![0; MAX_INPUT_SIZE + 1]).is_none());
    }

    #[test]
    fn operation_and_input_size_limits_are_enforced() {
        let mut maximum = sample_program();
        maximum.operations = vec![operation(Vec::new()); MAX_OPERATIONS];
        let encoded = maximum.encode().unwrap();
        assert_eq!(
            Program::parse(&encoded).unwrap().operations.len(),
            MAX_OPERATIONS
        );

        maximum.operations.push(operation(Vec::new()));
        assert!(maximum.encode().is_none());

        let mut too_many_records =
            vec![0; INPUT_HEADER_SIZE + (MAX_OPERATIONS + 1) * OP_HEADER_SIZE];
        too_many_records[HEADER_COUNT_OFFSET] = u8::try_from(MAX_OPERATIONS + 1).unwrap();
        assert!(Program::parse(&too_many_records).is_none());

        let mut max_input = sample_program();
        max_input.trailing.clear();
        max_input.operations[0].data = vec![0; MAX_INPUT_SIZE - INPUT_HEADER_SIZE - OP_HEADER_SIZE];
        let encoded = max_input.encode().unwrap();
        assert_eq!(encoded.len(), MAX_INPUT_SIZE);
        assert!(Program::parse(&encoded).is_some());
        max_input.operations[0].data.push(0);
        assert!(max_input.encode().is_none());
    }

    #[test]
    fn encoder_rejects_unencodable_records() {
        let mut program = sample_program();
        program.operations[0].slot = u8::try_from(SLOT_COUNT).unwrap();
        assert!(program.encoded_len().is_none());
        assert!(program.encode().is_none());
    }
}
