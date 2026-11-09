// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Regression traces for the invariant evaluator.

use super::*;
use crate::{invariant_spec::InvariantSpec, program::Operation, response};

const BAD_PARAMETERS: u32 = 0xffff_0006;

fn op(opcode: u8, slot: u8, selector: u8, aux: u16, data: &[u8]) -> Operation {
    Operation {
        opcode,
        slot,
        selector,
        aux,
        data: data.to_vec(),
    }
}

fn run(ops: Vec<Operation>, outcomes: &[(u32, &[u8])]) -> Vec<Check> {
    assert_eq!(ops.len(), outcomes.len());
    let mut wire = vec![0; OUTPUT_HEADER_SIZE + ops.len() * RESULT_SIZE];
    wire[..4].copy_from_slice(&OUTPUT_MAGIC);
    wire[4] = TA_VERSION;
    wire[HEADER_COUNT_OFFSET] = u8::try_from(ops.len()).unwrap();
    for (index, ((status, output), op)) in outcomes.iter().zip(&ops).enumerate() {
        let record = &mut wire[OUTPUT_HEADER_SIZE + index * RESULT_SIZE..][..RESULT_SIZE];
        record[..4].copy_from_slice(&status.to_le_bytes());
        record[4] = op.opcode;
        record[5] = op.slot;
        record[6..8].copy_from_slice(&u16::try_from(output.len()).unwrap().to_le_bytes());
        record[8..8 + output.len()].copy_from_slice(output);
    }
    let mut header = [0; INPUT_HEADER_SIZE];
    header[..4].copy_from_slice(&INPUT_MAGIC);
    header[4] = TA_VERSION;
    let program = Program {
        header,
        operations: ops,
        trailing: Vec::new(),
    };
    let steps: Vec<_> = response::parse(&wire).unwrap().collect();
    let spec = InvariantSpec::parse(include_str!("../../invariants.toml")).unwrap();
    evaluate_checks(&spec, &program, &steps)
        .into_iter()
        .filter(|check| !check.passed)
        .collect()
}

fn ids(findings: &[Check]) -> Vec<&str> {
    findings
        .iter()
        .map(|finding| finding.invariant.as_str())
        .collect()
}

#[test]
fn interleaved_sign_verify_uses_copied_material_and_exact_signature_source() {
    let digest = [7; 32];
    let sig = [0xa5; 128];
    let ops = vec![
        op(OP_OBJ_ALLOC, 0, 4, 1024, &[]),
        op(OP_OBJ_GENERATE_KEY, 0, 0, 1024, &[]),
        op(OP_OBJ_ALLOC, 1, 4, 1024, &[]),
        op(OP_OBJ_COPY, 1, 0, 0, &[]),
        op(OP_ALLOC, 0, 8, 0, &[]),
        op(OP_ASYMM_OPERATE, 0, 0, 128, &digest),
        op(OP_RANDOM, 7, 0, 1, &[]),
        op(OP_ALLOC, 1, 9, 1, &[]),
        op(OP_ASYMM_VERIFY, 1, 2, 5, &digest),
    ];
    let ok = (TEE_SUCCESS, &[][..]);
    let mut outcomes = vec![ok; ops.len()];
    outcomes[5] = (TEE_SUCCESS, &sig);
    outcomes[8] = (BAD_PARAMETERS, &[]);
    let findings = run(ops.clone(), &outcomes);
    assert!(ids(&findings).contains(&"sign_verify"));
    assert!(ids(&findings).contains(&"generated_key_sign_verify"));
    outcomes[8] = ok;
    assert!(run(ops.clone(), &outcomes).is_empty());
    outcomes[7] = (BAD_PARAMETERS, &[]);
    outcomes[8] = (BAD_PARAMETERS, &[]);
    assert!(run(ops.clone(), &outcomes).is_empty());
    outcomes[7] = ok;
    let mut wrong_source = ops;
    wrong_source[8].aux = 6;
    outcomes[8] = (BAD_PARAMETERS, &[]);
    assert!(run(wrong_source, &outcomes).is_empty());
}

#[test]
fn copied_aes_key_and_interleaved_cipher_result_are_checked() {
    let iv = [3; 16];
    let plain = b"hello";
    let cipher = [0x41; 5];
    let wrong = [0x40; 5];
    let ops = vec![
        op(OP_OBJ_ALLOC, 4, 2, 128, &[]),
        op(OP_OBJ_POPULATE, 4, 0, 0, &[1; 16]),
        op(OP_OBJ_ALLOC, 5, 2, 128, &[]),
        op(OP_OBJ_COPY, 5, 4, 0, &[]),
        op(OP_ALLOC, 0, 3, 5, &[]),
        op(OP_CIPHER_INIT, 0, 0, 0, &iv),
        op(OP_CIPHER_FINAL, 0, 0, 5, plain),
        op(OP_RANDOM, 7, 0, 1, &[]),
        op(OP_ALLOC, 1, 4, 4, &[]),
        op(OP_CIPHER_INIT, 1, 0, 0, &iv),
        op(OP_CIPHER_FINAL, 1, 0x80, 5, &[6]),
    ];
    let ok = (TEE_SUCCESS, &[][..]);
    let mut outcomes = vec![ok; ops.len()];
    outcomes[6] = (TEE_SUCCESS, &cipher);
    outcomes[10] = (TEE_SUCCESS, &wrong);
    let findings = run(ops.clone(), &outcomes);
    assert!(ids(&findings).contains(&"encrypt_decrypt"));
    assert!(ids(&findings).contains(&"copied_key_roundtrip"));
    outcomes[10] = (TEE_SUCCESS, plain);
    assert!(run(ops.clone(), &outcomes).is_empty());
    let mut unrelated = ops.clone();
    unrelated[10].data = vec![7];
    outcomes[10] = (TEE_SUCCESS, &wrong);
    assert!(run(unrelated, &outcomes).is_empty());

    let mut malformed_reference = ops.clone();
    malformed_reference[10].data.push(0);
    let mut malformed_outcomes = outcomes.clone();
    malformed_outcomes[10] = (BAD_PARAMETERS, &[]);
    assert!(run(malformed_reference, &malformed_outcomes).is_empty());

    let mut wrong_selector = ops.clone();
    wrong_selector[10].selector = 0x81;
    assert!(run(wrong_selector, &outcomes).is_empty());

    let mut shifted = ops;
    shifted.insert(6, op(OP_CIPHER_UPDATE, 0, 0, 1, b"x"));
    shifted[11].data = vec![7];
    let mut shifted_outcomes = outcomes.clone();
    shifted_outcomes.insert(6, (TEE_SUCCESS, &[0x5a]));
    assert!(run(shifted, &shifted_outcomes).is_empty());
}

#[test]
fn copied_secret_survives_source_reset_but_destination_mutation_invalidates_match() {
    let secret = [0x11; 16];
    let wrong = [0x22; 16];
    let ops = vec![
        op(OP_OBJ_ALLOC, 2, 0, 256, &[]),
        op(OP_OBJ_POPULATE, 2, 0, 0, &secret),
        op(OP_OBJ_ALLOC, 3, 0, 256, &[]),
        op(OP_OBJ_COPY, 3, 2, 0, &[]),
        op(OP_RANDOM, 7, 0, 1, &[]),
        op(OP_OBJ_RESET, 2, 0, 0, &[]),
        op(OP_OBJ_GET_ATTR, 3, 0, 16, &[]),
    ];
    let ok = (TEE_SUCCESS, &[][..]);
    let mut outcomes = vec![ok; ops.len()];
    outcomes[6] = (TEE_SUCCESS, &wrong);
    let findings = run(ops.clone(), &outcomes);
    assert!(ids(&findings).contains(&"copy_preserves_secret"));
    assert!(ids(&findings).contains(&"copy_is_independent"));
    outcomes[6] = (TEE_SUCCESS, &secret);
    assert!(run(ops, &outcomes).is_empty());

    let unextractable = vec![
        op(OP_OBJ_ALLOC, 2, 0, 256, &[]),
        op(OP_OBJ_POPULATE, 2, 0, 0, &secret),
        op(OP_OBJ_ALLOC, 3, 0, 256, &[]),
        op(OP_OBJ_RESTRICT_USAGE, 3, 0, 8, &[]),
        op(OP_OBJ_COPY, 3, 2, 0, &[]),
        op(OP_OBJ_GET_ATTR, 3, 0, 16, &[]),
    ];
    let mut failed_getter = vec![(TEE_SUCCESS, &[][..]); unextractable.len()];
    failed_getter[5] = (BAD_PARAMETERS, &[]);
    assert!(run(unextractable.clone(), &failed_getter).is_empty());
}

#[test]
fn reset_and_usage_metadata_decode_utee_object_info() {
    let mut initialized = [0u8; 28];
    initialized[24..28].copy_from_slice(&INITIALIZED.to_le_bytes());
    let mut wrong_usage = [0u8; 28];
    wrong_usage[12..16].copy_from_slice(&16u32.to_le_bytes());
    let ops = vec![
        op(OP_OBJ_ALLOC, 2, 0, 256, &[]),
        op(OP_OBJ_POPULATE, 2, 0, 0, &[1; 16]),
        op(OP_OBJ_RESET, 2, 0, 0, &[]),
        op(OP_OBJ_GET_INFO, 2, 0, 0, &[]),
        op(OP_OBJ_RESTRICT_USAGE, 2, 0, 8, &[]),
        op(OP_OBJ_GET_INFO, 2, 0, 0, &[]),
    ];
    let ok = (TEE_SUCCESS, &[][..]);
    let mut outcomes = vec![ok; ops.len()];
    outcomes[3] = (TEE_SUCCESS, &initialized);
    outcomes[5] = (TEE_SUCCESS, &wrong_usage);
    let findings = run(ops, &outcomes);
    assert!(ids(&findings).contains(&"reset_uninitializes"));
    assert!(ids(&findings).contains(&"restrict_usage"));
}

#[test]
fn aead_roundtrip_requires_matching_nonce_aad_and_source() {
    let nonce = [2; 12];
    let aad = b"aad";
    let plain = b"hello";
    let ciphertext = [0x55; 5];
    let wrong = [0x56; 5];
    let ops = vec![
        op(OP_OBJ_ALLOC, 4, 2, 128, &[]),
        op(OP_OBJ_POPULATE, 4, 0, 0, &[1; 16]),
        op(OP_OBJ_ALLOC, 5, 2, 128, &[]),
        op(OP_OBJ_COPY, 5, 4, 0, &[]),
        op(OP_ALLOC, 0, 5, 4, &[]),
        op(OP_AUTHENC_INIT, 0, 16, 0x0305, &nonce),
        op(OP_AUTHENC_UPDATE_AAD, 0, 0, 0, aad),
        op(OP_AUTHENC_ENC_FINAL, 0, 16, 5, plain),
        op(OP_RANDOM, 7, 0, 1, &[]),
        op(OP_ALLOC, 1, 6, 5, &[]),
        op(OP_AUTHENC_INIT, 1, 16, 0x0305, &nonce),
        op(OP_AUTHENC_UPDATE_AAD, 1, 0, 0, aad),
        op(OP_AUTHENC_DEC_FINAL, 1, 0x90, 5, &[7]),
    ];
    let ok = (TEE_SUCCESS, &[][..]);
    let mut outcomes = vec![ok; ops.len()];
    outcomes[7] = (TEE_SUCCESS, &ciphertext);
    outcomes[12] = (TEE_SUCCESS, &wrong);
    assert!(ids(&run(ops.clone(), &outcomes)).contains(&"aead_roundtrip"));
    let mut mismatched_aad = ops;
    mismatched_aad[11].data = b"bad".to_vec();
    assert!(run(mismatched_aad, &outcomes).is_empty());
}

#[test]
fn copied_public_key_and_usage_failures_are_separate_checks() {
    let digest = [0x33; 32];
    let signature = [0x44; 128];
    let public_ops = vec![
        op(OP_OBJ_ALLOC, 0, 4, 1024, &[]),
        op(OP_OBJ_GENERATE_KEY, 0, 0, 1024, &[]),
        op(OP_OBJ_ALLOC, 1, 5, 1024, &[]),
        op(OP_OBJ_COPY, 1, 0, 0, &[]),
        op(OP_ALLOC, 0, 8, 0, &[]),
        op(OP_ASYMM_OPERATE, 0, 0, 128, &digest),
        op(OP_ALLOC, 1, 9, 1, &[]),
        op(OP_ASYMM_VERIFY, 1, 2, 5, &digest),
    ];
    let ok = (TEE_SUCCESS, &[][..]);
    let mut outcomes = vec![ok; public_ops.len()];
    outcomes[5] = (TEE_SUCCESS, &signature);
    outcomes[7] = (BAD_PARAMETERS, &[]);
    assert!(ids(&run(public_ops, &outcomes)).contains(&"copied_public_key_verify"));

    let mut wrong_usage = [0u8; 28];
    wrong_usage[12..16].copy_from_slice(&16u32.to_le_bytes());
    let usage_ops = vec![
        op(OP_OBJ_ALLOC, 2, 0, 256, &[]),
        op(OP_OBJ_POPULATE, 2, 0, 0, &[1; 16]),
        op(OP_OBJ_RESTRICT_USAGE, 2, 0, 8, &[]),
        op(OP_OBJ_ALLOC, 3, 0, 256, &[]),
        op(OP_OBJ_COPY, 3, 2, 0, &[]),
        op(OP_OBJ_GET_INFO, 3, 0, 0, &[]),
    ];
    let mut outcomes = vec![ok; usage_ops.len()];
    outcomes[5] = (TEE_SUCCESS, &wrong_usage);
    assert!(ids(&run(usage_ops, &outcomes)).contains(&"copy_preserves_usage"));
}
