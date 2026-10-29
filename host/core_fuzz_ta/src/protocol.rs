// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Wire-format constants generated from `ta/core_fuzz_ta/include/core_fuzz_ta.h`.

include!(concat!(env!("OUT_DIR"), "/core_fuzz_ta_protocol.rs"));

/// `TEE_SUCCESS`, the status stored in a successful result record.
pub const TEE_SUCCESS: u32 = 0;

/// Offset of the operation count in the input and response headers.
pub const HEADER_COUNT_OFFSET: usize = 5;

/// Size of the fixed part of a result record, before its output bytes.
pub const RESULT_HEADER_SIZE: usize = 8;

// Invariants the Rust code relies on. A header change that breaks one of them
// fails the build here instead of truncating values at run time.
const _: () = {
    assert!(
        MAX_OPERATIONS <= u8::MAX as usize,
        "operation count is a byte"
    );
    assert!(SLOT_COUNT <= u8::MAX as usize, "slot index is a byte");
    assert!(
        OPCODE_COUNT == MAX_OPCODE as usize,
        "opcodes are 1..=OPCODE_COUNT"
    );
    assert!(INPUT_HEADER_SIZE > HEADER_COUNT_OFFSET);
    assert!(OUTPUT_HEADER_SIZE > HEADER_COUNT_OFFSET);
    assert!(RESULT_SIZE == RESULT_HEADER_SIZE + RESULT_DATA_SIZE);
    assert!(MAX_OUTPUT_SIZE == OUTPUT_HEADER_SIZE + MAX_OPERATIONS * RESULT_SIZE);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the wire contract: any change here needs a new
    /// `CORE_FUZZ_TA_VERSION` and regenerated seeds.
    #[test]
    fn host_protocol_constants_match_the_ta_wire_contract() {
        assert_eq!(&INPUT_MAGIC, b"FZP2");
        assert_eq!(&OUTPUT_MAGIC, b"FZR2");
        assert_eq!(TA_VERSION, 2);
        assert_eq!(MAX_INPUT_SIZE, 4096);
        assert_eq!(MAX_OPERATIONS, 64);
        assert_eq!(SLOT_COUNT, 8);
        assert_eq!(INPUT_HEADER_SIZE, 8);
        assert_eq!(OP_HEADER_SIZE, 7);
        assert_eq!(OUTPUT_HEADER_SIZE, 8);
        assert_eq!(RESULT_SIZE, 40);
        assert_eq!(RESULT_DATA_SIZE, 32);
    }

    #[test]
    fn opcode_numbers_remain_contiguous_and_stable() {
        let opcodes = [
            OP_ALLOC,
            OP_INIT,
            OP_UPDATE,
            OP_FINAL,
            OP_FREE,
            OP_OBJ_ALLOC,
            OP_OBJ_POPULATE,
            OP_OBJ_CLOSE,
            OP_OBJ_GET_INFO,
            OP_OBJ_RESTRICT_USAGE,
            OP_OBJ_RESET,
            OP_OBJ_GET_ATTR,
            OP_OBJ_COPY,
            OP_OBJ_GENERATE_KEY,
            OP_STATE_COPY,
            OP_CIPHER_INIT,
            OP_CIPHER_UPDATE,
            OP_CIPHER_FINAL,
            OP_DERIVE_KEY,
            OP_RANDOM,
            OP_AUTHENC_INIT,
            OP_AUTHENC_UPDATE_AAD,
            OP_AUTHENC_UPDATE_PAYLOAD,
            OP_AUTHENC_ENC_FINAL,
            OP_AUTHENC_DEC_FINAL,
            OP_ASYMM_OPERATE,
            OP_ASYMM_VERIFY,
        ];
        assert_eq!(opcodes.len(), OPCODE_COUNT);
        assert!(opcodes.iter().copied().eq(1..=MAX_OPCODE));
    }
}
