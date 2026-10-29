// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Crypto operation field values used by the structure-aware mutator.
//!
//! These tables track the selectors, `aux` values and payload boundaries
//! understood by the crypto service opcodes in the TA.

use crate::protocol::{
    OP_ALLOC, OP_ASYMM_OPERATE, OP_ASYMM_VERIFY, OP_AUTHENC_DEC_FINAL, OP_AUTHENC_ENC_FINAL,
    OP_AUTHENC_INIT, OP_AUTHENC_UPDATE_PAYLOAD, OP_CIPHER_FINAL, OP_CIPHER_UPDATE, OP_DERIVE_KEY,
    OP_FINAL, OP_OBJ_ALLOC, OP_OBJ_GENERATE_KEY, OP_OBJ_GET_ATTR, OP_OBJ_GET_INFO, OP_OBJ_POPULATE,
    OP_OBJ_RESTRICT_USAGE, OP_RANDOM, OP_STATE_COPY, SLOT_COUNT,
};

// Selector values understood by the TA for each opcode family; see
// `ta/core_fuzz_ta/README.md`.
const ALLOC_SELECTORS: [u8; 18] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
const OBJECT_SELECTORS: [u8; 6] = [0, 1, 2, 3, 4, 5];
const SMALL_SELECTORS: [u8; 4] = [0, 1, 2, 3];
const BOOL_SELECTORS: [u8; 2] = [0, 1];
const SLOT_SELECTORS: [u8; SLOT_COUNT] = [0, 1, 2, 3, 4, 5, 6, 7];
const TAG_SELECTORS: [u8; 7] = [0, 1, 4, 8, 12, 16, 17];

// Boundary values for the 16-bit `aux` field.
const GENERAL_AUX: [u16; 13] = [0, 1, 2, 4, 7, 8, 16, 31, 32, 64, 128, 256, u16::MAX];
const SLOT_AUX: [u16; SLOT_COUNT] = [0, 1, 2, 3, 4, 5, 6, 7];
const FINAL_AUX: [u16; 6] = [0, 1, 31, 32, 33, 64];
const OBJECT_SIZE_AUX: [u16; 8] = [0, 8, 128, 192, 256, 512, 1024, 2048];
const ATTRIBUTE_AUX: [u16; 7] = [0, 1, 8, 16, 31, 32, 64];
const USAGE_AUX: [u16; 3] = [0, 8, u16::MAX];
const OUTPUT_AUX: [u16; 9] = [0, 1, 16, 31, 32, 64, 128, 256, 257];
const AUTHENC_AUX: [u16; 5] = [0, 1, 0x0101, 0x0305, 0x0405];
const VERIFY_AUX: [u16; 6] = [0, 1, 16, 32, 64, 256];
pub(crate) const DATA_LENGTHS: [usize; 11] = [0, 1, 2, 12, 16, 31, 32, 63, 64, 128, 256];

pub(crate) fn selector_values(opcode: u8) -> &'static [u8] {
    match opcode {
        OP_ALLOC => &ALLOC_SELECTORS,
        OP_OBJ_ALLOC => &OBJECT_SELECTORS,
        OP_OBJ_POPULATE | OP_ASYMM_VERIFY => &BOOL_SELECTORS,
        OP_STATE_COPY | OP_DERIVE_KEY => &SLOT_SELECTORS,
        OP_AUTHENC_INIT | OP_AUTHENC_ENC_FINAL | OP_AUTHENC_DEC_FINAL => &TAG_SELECTORS,
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
        OP_ASYMM_VERIFY => &VERIFY_AUX,
        _ => &GENERAL_AUX,
    }
}
