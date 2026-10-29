// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Normal-world side of the runner: libteec client, coverage map, campaign
//! and replay loops. Everything here runs in the OP-TEE QEMU guest.

mod coverage;
mod fuzz;
mod replay;
mod teec;

use std::{
    error::Error,
    io::{self, Write},
};

use core_fuzz_ta_libafl::{
    cli::RunMode,
    response::{OpcodeStats, Steps},
};

/// Runs the mode selected on the command line.
pub(crate) fn run(mode: &RunMode) -> Result<(), Box<dyn Error>> {
    match mode {
        RunMode::Fuzz(config) => fuzz::run(config),
        RunMode::Replay(config) => replay::run(config),
    }
}

/// Counts each step and prints a `FUZZ_OPCODE_STEP` line for defined opcodes.
fn print_opcode_steps(steps: Steps<'_>, stats: &mut OpcodeStats) {
    let mut out = io::stdout().lock();
    for step in steps {
        if let Some(count) = stats.record(&step) {
            // A closed stdout must not stop the campaign; counting continues.
            let _ = writeln!(
                out,
                "FUZZ_OPCODE_STEP opcode={} result=0x{:08x} calls={} success={}",
                step.opcode, step.status, count.calls, count.successes
            );
        }
    }
}

/// Prints the final `FUZZ_OPCODE` totals.
fn print_opcode_totals(stats: &OpcodeStats) {
    for (opcode, count) in stats.iter() {
        println!(
            "FUZZ_OPCODE opcode={opcode} calls={} success={}",
            count.calls, count.successes
        );
    }
}
