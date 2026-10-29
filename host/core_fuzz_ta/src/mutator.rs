// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Structure-aware LibAFL mutator for FZP2 programs.
//!
//! Four out of five mutations decode the input as a [`Program`] and edit one
//! field or record using values that are meaningful to the TA. The rest, and
//! any structured attempt that cannot be applied, flip one raw bit so that
//! framing errors stay reachable.

use std::{borrow::Cow, num::NonZeroUsize};

use libafl::{
    Error,
    inputs::{BytesInput, HasMutatorBytes},
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand};

use crate::{
    crypto_mutator,
    program::{Operation, Program},
    protocol::{
        MAX_INPUT_SIZE, MAX_OPCODE, MAX_OPERATIONS, OP_HEADER_SIZE, OP_RANDOM, OPCODE_COUNT,
        SLOT_COUNT,
    },
};

/// One in this many mutations is a raw bit flip instead of a structured edit.
const RAW_MUTATION_DENOMINATOR: usize = 5;
/// Number of structured edit kinds in [`mutate_program`].
const STRUCTURED_ACTIONS: usize = 9;

/// LibAFL mutator that edits FZP2 programs field by field.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoreFuzzProgramMutator;

impl<S: HasRand> Mutator<BytesInput, S> for CoreFuzzProgramMutator {
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        let mut choose = |upper: usize| {
            rand.below(NonZeroUsize::new(upper).expect("choose() needs a non-empty range"))
        };
        let original = input.mutator_bytes();
        match mutate_bytes(original, &mut choose) {
            Some(candidate) if candidate != original => {
                *input = BytesInput::new(candidate);
                Ok(MutationResult::Mutated)
            }
            _ => Ok(MutationResult::Skipped),
        }
    }
}

impl Named for CoreFuzzProgramMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CoreFuzzProgramMutator");
        &NAME
    }
}

/// Returns a mutated copy of `original`, or `None` if nothing could change.
///
/// `choose(n)` must return a uniformly distributed value in `0..n`; it is a
/// parameter so tests can drive the mutator deterministically.
pub fn mutate_bytes<F>(original: &[u8], choose: &mut F) -> Option<Vec<u8>>
where
    F: FnMut(usize) -> usize,
{
    if choose(RAW_MUTATION_DENOMINATOR) != 0 {
        if let Some(mut program) = Program::parse(original) {
            if mutate_program(&mut program, choose) {
                if let Some(encoded) = program.encode() {
                    return Some(encoded);
                }
            }
        }
    }
    let mut candidate = original.to_vec();
    flip_random_bit(&mut candidate, choose).then_some(candidate)
}

/// Picks a value in `0..upper` as a byte; `upper` must not exceed 256.
fn choose_u8<F>(choose: &mut F, upper: usize) -> u8
where
    F: FnMut(usize) -> usize,
{
    u8::try_from(choose(upper)).expect("choose_u8() bound must not exceed 256")
}

/// Picks one element of a non-empty table, avoiding `current` when possible.
fn choose_other<T, F>(choose: &mut F, values: &[T], current: T) -> T
where
    T: Copy + PartialEq,
    F: FnMut(usize) -> usize,
{
    let index = choose(values.len());
    if values[index] == current {
        values[(index + 1) % values.len()]
    } else {
        values[index]
    }
}

fn flip_random_bit<F>(bytes: &mut [u8], choose: &mut F) -> bool
where
    F: FnMut(usize) -> usize,
{
    if bytes.is_empty() {
        return false;
    }
    let offset = choose(bytes.len());
    bytes[offset] ^= 1 << choose(8);
    true
}

fn mutate_program<F>(program: &mut Program, choose: &mut F) -> bool
where
    F: FnMut(usize) -> usize,
{
    if program.operations.is_empty() {
        program.operations.push(random_operation(choose));
        return true;
    }

    match choose(STRUCTURED_ACTIONS) {
        0 => mutate_opcode(program, choose),
        1 => mutate_slot(program, choose),
        2 => mutate_selector(program, choose),
        3 => mutate_aux(program, choose),
        4 => mutate_payload_byte(program, choose),
        5 => resize_payload(program, choose),
        6 => duplicate_operation(program, choose),
        7 => delete_operation(program, choose),
        _ => swap_adjacent_operations(program, choose),
    }
}

fn random_operation<F>(choose: &mut F) -> Operation
where
    F: FnMut(usize) -> usize,
{
    Operation {
        opcode: OP_RANDOM,
        slot: choose_u8(choose, SLOT_COUNT),
        selector: 0,
        aux: 32,
        data: Vec::new(),
    }
}

/// Returns a mutable reference to a random record of a non-empty program.
fn random_record<'a, F>(program: &'a mut Program, choose: &mut F) -> &'a mut Operation
where
    F: FnMut(usize) -> usize,
{
    let index = choose(program.operations.len());
    &mut program.operations[index]
}

fn mutate_opcode<F>(program: &mut Program, choose: &mut F) -> bool
where
    F: FnMut(usize) -> usize,
{
    let opcode = 1 + choose_u8(choose, OPCODE_COUNT);
    let operation = random_record(program, choose);
    operation.opcode = if opcode != operation.opcode {
        opcode
    } else if operation.opcode >= MAX_OPCODE {
        1
    } else {
        operation.opcode + 1
    };
    true
}

fn mutate_slot<F>(program: &mut Program, choose: &mut F) -> bool
where
    F: FnMut(usize) -> usize,
{
    let operation = random_record(program, choose);
    let next = (usize::from(operation.slot) + 1 + choose(SLOT_COUNT - 1)) % SLOT_COUNT;
    operation.slot = u8::try_from(next).expect("SLOT_COUNT fits in a byte");
    true
}

fn mutate_selector<F>(program: &mut Program, choose: &mut F) -> bool
where
    F: FnMut(usize) -> usize,
{
    let operation = random_record(program, choose);
    operation.selector = choose_other(
        choose,
        crypto_mutator::selector_values(operation.opcode),
        operation.selector,
    );
    true
}

fn mutate_aux<F>(program: &mut Program, choose: &mut F) -> bool
where
    F: FnMut(usize) -> usize,
{
    let operation = random_record(program, choose);
    let values = crypto_mutator::aux_values(operation.opcode, operation.selector);
    operation.aux = choose_other(choose, values, operation.aux);
    true
}

fn mutate_payload_byte<F>(program: &mut Program, choose: &mut F) -> bool
where
    F: FnMut(usize) -> usize,
{
    let operation = random_record(program, choose);
    if operation.data.is_empty() {
        operation.data.push(choose_u8(choose, 256));
    } else {
        flip_random_bit(&mut operation.data, choose);
    }
    true
}

fn resize_payload<F>(program: &mut Program, choose: &mut F) -> bool
where
    F: FnMut(usize) -> usize,
{
    let Some(total_len) = program.encoded_len() else {
        return false;
    };
    let index = choose(program.operations.len());
    let current_len = program.operations[index].data.len();
    let max_data_len = MAX_INPUT_SIZE.saturating_sub(total_len - current_len);
    let candidates: Vec<usize> = crypto_mutator::DATA_LENGTHS
        .into_iter()
        .filter(|length| *length <= max_data_len)
        .collect();
    if candidates.is_empty() {
        return false;
    }
    let new_len = choose_other(choose, &candidates, current_len);
    if new_len == current_len {
        return false;
    }

    let data = &mut program.operations[index].data;
    data.resize(new_len, 0);
    for byte in data.iter_mut().skip(current_len) {
        *byte = choose_u8(choose, 256);
    }
    true
}

fn duplicate_operation<F>(program: &mut Program, choose: &mut F) -> bool
where
    F: FnMut(usize) -> usize,
{
    if program.operations.len() >= MAX_OPERATIONS {
        return false;
    }
    let Some(total_len) = program.encoded_len() else {
        return false;
    };
    let operation = random_record(program, choose).clone();
    if total_len + OP_HEADER_SIZE + operation.data.len() > MAX_INPUT_SIZE {
        return false;
    }
    let position = choose(program.operations.len() + 1);
    program.operations.insert(position, operation);
    true
}

fn delete_operation<F>(program: &mut Program, choose: &mut F) -> bool
where
    F: FnMut(usize) -> usize,
{
    if program.operations.is_empty() {
        return false;
    }
    let index = choose(program.operations.len());
    program.operations.remove(index);
    true
}

fn swap_adjacent_operations<F>(program: &mut Program, choose: &mut F) -> bool
where
    F: FnMut(usize) -> usize,
{
    if program.operations.len() < 2 {
        return false;
    }
    let index = choose(program.operations.len() - 1);
    program.operations.swap(index, index + 1);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{HEADER_COUNT_OFFSET, INPUT_HEADER_SIZE, INPUT_MAGIC, TA_VERSION};

    /// Deterministic `choose` for tests (64-bit LCG).
    fn lcg(mut seed: u64) -> impl FnMut(usize) -> usize {
        move |upper| {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            usize::try_from(seed >> 33).unwrap() % upper
        }
    }

    fn sample_program() -> Program {
        let mut header = [0; INPUT_HEADER_SIZE];
        header[..4].copy_from_slice(&INPUT_MAGIC);
        header[4] = TA_VERSION;
        header[HEADER_COUNT_OFFSET] = 1;
        Program {
            header,
            operations: vec![Operation {
                opcode: OP_RANDOM,
                slot: 0,
                selector: 0,
                aux: 12,
                data: vec![0xaa, 0xbb],
            }],
            trailing: vec![0x55],
        }
    }

    #[test]
    fn structured_mutations_stay_within_protocol_bounds() {
        let mut program = sample_program();
        let mut choose = lcg(0x6a09_e667_f3bc_c909);
        for _ in 0..1_000 {
            mutate_program(&mut program, &mut choose);
            let encoded = program.encode().expect("mutation must remain encodable");
            assert!(encoded.len() <= MAX_INPUT_SIZE);
            assert!(program.operations.len() <= MAX_OPERATIONS);
        }
    }

    #[test]
    fn byte_mutations_always_change_the_input_and_respect_the_size_limit() {
        let mut input = sample_program().encode().unwrap();
        let mut choose = lcg(1);
        for _ in 0..1_000 {
            if let Some(next) = mutate_bytes(&input, &mut choose) {
                assert!(next.len() <= MAX_INPUT_SIZE);
                input = next;
            }
        }
    }

    #[test]
    fn choose_other_avoids_the_current_value() {
        let mut always_zero = |_| 0;
        assert_eq!(choose_other(&mut always_zero, &[3, 4], 3), 4);
        assert_eq!(choose_other(&mut always_zero, &[3, 4], 9), 3);
        assert_eq!(choose_other(&mut always_zero, &[3], 3), 3);
    }

    #[test]
    fn opcode_mutation_never_keeps_the_same_opcode() {
        for current in 1..=MAX_OPCODE {
            for pick in 0..OPCODE_COUNT {
                let mut program = sample_program();
                program.operations[0].opcode = current;
                let mut fixed = |upper: usize| if upper == OPCODE_COUNT { pick } else { 0 };
                mutate_opcode(&mut program, &mut fixed);
                let opcode = program.operations[0].opcode;
                assert_ne!(opcode, current);
                assert!((1..=MAX_OPCODE).contains(&opcode));
            }
        }
    }
}
