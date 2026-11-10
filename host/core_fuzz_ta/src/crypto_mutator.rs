// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Crypto operation field values used by the structure-aware mutator.
//!
//! These tables track the selectors, `aux` values and payload boundaries
//! understood by the crypto service opcodes in the TA.

use crate::protocol::{
    OP_ALLOC, OP_ASYMM_OPERATE, OP_ASYMM_VERIFY, OP_AUTHENC_DEC_FINAL, OP_AUTHENC_ENC_FINAL,
    OP_AUTHENC_INIT, OP_AUTHENC_UPDATE_PAYLOAD, OP_CIPHER_FINAL, OP_CIPHER_UPDATE, OP_DERIVE_KEY,
    OP_FINAL, OP_OBJ_ALLOC, OP_OBJ_COPY, OP_OBJ_GENERATE_KEY, OP_OBJ_GET_ATTR, OP_OBJ_GET_INFO,
    OP_OBJ_POPULATE, OP_OBJ_RESTRICT_USAGE, OP_RANDOM, OP_STATE_COPY, OP_UPDATE, SLOT_COUNT,
};

// Selector values understood by the TA for each opcode family; see
// `ta/core_fuzz_ta/README.md`.
const ALLOC_SELECTORS: [u8; 20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
];
const OBJECT_SELECTORS: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
const SMALL_SELECTORS: [u8; 4] = [0, 1, 2, 3];
const BOOL_SELECTORS: [u8; 2] = [0, 1];
const CIPHER_SELECTORS: [u8; 2] = [0, 0x80];
const ASYMM_SELECTORS: [u8; 3] = [0, 1, 2];
const SLOT_SELECTORS: [u8; SLOT_COUNT] = [0, 1, 2, 3, 4, 5, 6, 7];
const TAG_SELECTORS: [u8; 7] = [0, 1, 4, 8, 12, 16, 17];
const TAG_DEC_SELECTORS: [u8; 14] = [
    0, 1, 4, 8, 12, 16, 17, 0x80, 0x81, 0x84, 0x88, 0x8c, 0x90, 0x91,
];

// Boundary values for the 16-bit `aux` field.
const GENERAL_AUX: [u16; 13] = [0, 1, 2, 4, 7, 8, 16, 31, 32, 64, 128, 256, u16::MAX];
const SLOT_AUX: [u16; SLOT_COUNT] = [0, 1, 2, 3, 4, 5, 6, 7];
const FINAL_AUX: [u16; 6] = [0, 1, 31, 32, 33, 64];
const OBJECT_SIZE_AUX: [u16; 8] = [0, 8, 128, 192, 256, 512, 1024, 2048];
const ATTRIBUTE_AUX: [u16; 10] = [0, 1, 8, 16, 31, 32, 64, 128, 255, 256];
const USAGE_AUX: [u16; 3] = [0, 8, u16::MAX];
const OUTPUT_AUX: [u16; 9] = [0, 1, 16, 31, 32, 64, 128, 256, 257];
const AUTHENC_AUX: [u16; 5] = [0, 1, 0x0101, 0x0305, 0x0405];
const VERIFY_AUX: [u16; 6] = [0, 1, 16, 32, 64, 256];
const STEP_INDEX_AUX: [u16; 8] = [0, 1, 2, 3, 5, 7, 31, 63];
pub(crate) const DATA_LENGTHS: [usize; 11] = [0, 1, 2, 12, 16, 31, 32, 63, 64, 128, 256];
const DIGEST_EDGES: [u16; 6] = [31, 32, 33, 63, 64, 65];
const ATTRIBUTE_EDGES: [u16; 9] = [15, 16, 17, 31, 32, 33, 255, 256, 257];
const RSA_OUTPUT_EDGES: [u16; 5] = [127, 128, 129, 255, 256];
const BLOCK_EDGES: [usize; 9] = [0, 1, 15, 16, 17, 31, 32, 33, 256];
const NONCE_EDGES: [usize; 6] = [6, 7, 11, 12, 13, 14];
const HASH_EDGES: [usize; 17] = [
    0, 1, 31, 32, 33, 55, 56, 57, 63, 64, 65, 111, 112, 113, 127, 128, 129,
];

pub(crate) fn selector_values(opcode: u8) -> &'static [u8] {
    match opcode {
        OP_ALLOC => &ALLOC_SELECTORS,
        OP_OBJ_ALLOC => &OBJECT_SELECTORS,
        OP_OBJ_POPULATE | OP_OBJ_GENERATE_KEY => &BOOL_SELECTORS,
        OP_ASYMM_OPERATE | OP_ASYMM_VERIFY => &ASYMM_SELECTORS,
        OP_OBJ_COPY | OP_STATE_COPY | OP_DERIVE_KEY => &SLOT_SELECTORS,
        OP_CIPHER_UPDATE | OP_CIPHER_FINAL => &CIPHER_SELECTORS,
        OP_AUTHENC_INIT | OP_AUTHENC_ENC_FINAL => &TAG_SELECTORS,
        OP_AUTHENC_DEC_FINAL => &TAG_DEC_SELECTORS,
        // OP_OBJ_GET_ATTR passes non-zero selectors through as attribute IDs.
        _ => &SMALL_SELECTORS,
    }
}

pub(crate) fn aux_values(opcode: u8, selector: u8) -> &'static [u16] {
    match opcode {
        OP_ALLOC if selector >= 2 => &SLOT_AUX,
        OP_FINAL => &FINAL_AUX,
        OP_OBJ_ALLOC | OP_OBJ_GENERATE_KEY => &OBJECT_SIZE_AUX,
        OP_OBJ_GET_INFO | OP_OBJ_GET_ATTR => &ATTRIBUTE_AUX,
        OP_OBJ_RESTRICT_USAGE => &USAGE_AUX,
        OP_CIPHER_UPDATE
        | OP_CIPHER_FINAL
        | OP_DERIVE_KEY
        | OP_RANDOM
        | OP_AUTHENC_UPDATE_PAYLOAD
        | OP_AUTHENC_ENC_FINAL
        | OP_AUTHENC_DEC_FINAL
        | OP_ASYMM_OPERATE => &OUTPUT_AUX,
        OP_AUTHENC_INIT => &AUTHENC_AUX,
        OP_ASYMM_VERIFY if selector == 2 => &STEP_INDEX_AUX,
        OP_ASYMM_VERIFY => &VERIFY_AUX,
        _ => &GENERAL_AUX,
    }
}

/// Output capacities immediately around the size checked by the core syscall.
/// The TA itself rejects capacities above its 256-byte temporary buffer.
pub(crate) fn boundary_aux_values(opcode: u8, selector: u8, data_len: usize) -> Vec<u16> {
    match opcode {
        OP_FINAL => DIGEST_EDGES.to_vec(),
        OP_OBJ_GET_ATTR => ATTRIBUTE_EDGES.to_vec(),
        OP_CIPHER_UPDATE
        | OP_CIPHER_FINAL
        | OP_AUTHENC_UPDATE_PAYLOAD
        | OP_AUTHENC_ENC_FINAL
        | OP_AUTHENC_DEC_FINAL => {
            let required = if (opcode == OP_AUTHENC_DEC_FINAL && selector & 0x80 != 0)
                || (matches!(opcode, OP_CIPHER_UPDATE | OP_CIPHER_FINAL) && selector == 0x80)
            {
                // Reference mode's one-byte payload is a step index; the
                // source ciphertext length is only known at execution time.
                return OUTPUT_AUX.to_vec();
            } else if opcode == OP_AUTHENC_DEC_FINAL {
                data_len.saturating_sub(usize::from(if selector == 0 { 16 } else { selector }))
            } else {
                data_len
            };
            let mut values = vec![0, 1];
            for size in [
                required.saturating_sub(1),
                required,
                required.saturating_add(1),
            ] {
                if size <= 256 {
                    let size = u16::try_from(size).expect("temporary output size fits u16");
                    if !values.contains(&size) {
                        values.push(size);
                    }
                }
            }
            values
        }
        OP_ASYMM_OPERATE => RSA_OUTPUT_EDGES.to_vec(),
        _ => aux_values(opcode, selector).to_vec(),
    }
}

/// Payload lengths near actual AES block, hash block, and nonce boundaries.
pub(crate) fn boundary_data_lengths(opcode: u8) -> &'static [usize] {
    match opcode {
        OP_CIPHER_UPDATE
        | OP_CIPHER_FINAL
        | OP_AUTHENC_UPDATE_PAYLOAD
        | OP_AUTHENC_ENC_FINAL
        | OP_AUTHENC_DEC_FINAL => &BLOCK_EDGES,
        OP_AUTHENC_INIT => &NONCE_EDGES,
        OP_UPDATE | OP_FINAL => &HASH_EDGES,
        _ => &DATA_LENGTHS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_edges_match_the_syscall_output_size() {
        assert!(boundary_aux_values(OP_FINAL, 0, 0).contains(&31));
        assert!(boundary_aux_values(OP_FINAL, 0, 0).contains(&64));
        assert!(boundary_aux_values(OP_FINAL, 0, 0).contains(&65));
        assert_eq!(
            boundary_aux_values(OP_CIPHER_UPDATE, 0, 16),
            [0, 1, 15, 16, 17]
        );
        assert_eq!(
            boundary_aux_values(OP_AUTHENC_DEC_FINAL, 16, 21),
            [0, 1, 4, 5, 6]
        );
        assert!(boundary_aux_values(OP_OBJ_GET_ATTR, 0, 0).contains(&31));
        assert!(boundary_aux_values(OP_OBJ_GET_ATTR, 0, 0).contains(&33));
        assert!(boundary_aux_values(OP_ASYMM_OPERATE, 0, 0).contains(&127));
        assert!(!boundary_aux_values(OP_CIPHER_UPDATE, 0, 256).contains(&257));
        assert!(boundary_data_lengths(OP_UPDATE).contains(&56));
        assert!(boundary_data_lengths(OP_FINAL).contains(&112));
    }
}
