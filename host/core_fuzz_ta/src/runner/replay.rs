// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! One-shot replay of a saved input.

use std::{error::Error, fmt::Write as _, fs};

use core_fuzz_ta_libafl::{
    cli::ReplayConfig,
    protocol::{MAX_INPUT_SIZE, MAX_OUTPUT_SIZE, OP_FINAL},
    response::{self, OpcodeStats, Steps},
};

use super::{coverage::CoverageMap, print_opcode_steps, print_opcode_totals, teec::TeecContext};

/// Exit status reported when at least one invocation failed.
const FAILED_STATUS: u8 = 2;

/// Prints one `step=...` line per result record.
fn print_steps(steps: Steps<'_>) {
    for (index, step) in steps.enumerate() {
        let mut line = format!(
            "step={index} opcode={} slot={} status=0x{:08x} output_len={}",
            step.opcode, step.slot, step.status, step.reported_len
        );
        if step.opcode == OP_FINAL && step.succeeded() {
            line.push_str(" digest=");
            for byte in step.data() {
                let _ = write!(line, "{byte:02x}");
            }
        }
        println!("{line}");
    }
}

/// Runs the input once; returns `Ok(false)` if the invocation failed.
fn run_once(
    teec: &TeecContext,
    coverage: &mut CoverageMap,
    input: &[u8],
    run_index: u64,
    stats: &mut OpcodeStats,
) -> Result<bool, Box<dyn Error>> {
    let mut response = [0u8; MAX_OUTPUT_SIZE];
    let invocation = teec.run(input, &mut response, coverage);
    let result = invocation.result;

    if !invocation.succeeded() {
        if invocation.target_dead() {
            println!("run={run_index} invoke=0x{result:08x} classification=TA_TARGET_DEAD");
        } else {
            println!("run={run_index} invoke=0x{result:08x}");
        }
        return Ok(false);
    }
    let response = response
        .get(..invocation.response_len)
        .ok_or_else(|| format!("invalid response size: {}", invocation.response_len))?;
    if invocation.coverage_len != coverage.len() {
        return Err(format!("invalid coverage map length: {}", invocation.coverage_len).into());
    }

    let coverage_nonzero = coverage
        .as_slice()
        .iter()
        .filter(|&&byte| byte != 0)
        .count();
    println!(
        "run={run_index} invoke=0x{result:08x} coverage_scope=whole coverage_bytes={} \
         coverage_nonzero={coverage_nonzero}",
        invocation.coverage_len
    );
    let steps = response::parse(response)?;
    print_steps(steps.clone());
    print_opcode_steps(steps, stats);
    Ok(true)
}

/// Replays `config.input_file` `config.repeats` times.
pub(crate) fn run(config: &ReplayConfig) -> Result<(), Box<dyn Error>> {
    let input = fs::read(&config.input_file)?;
    if input.len() > MAX_INPUT_SIZE {
        return Err(format!("input exceeds {MAX_INPUT_SIZE} bytes: {}", input.len()).into());
    }
    println!(
        "FUZZ_REPLAY input={} bytes={} repeats={}",
        config.input_file.display(),
        input.len(),
        config.repeats
    );

    let teec = TeecContext::new()?;
    let mut coverage = CoverageMap::new();
    let mut stats = OpcodeStats::default();
    let mut status = 0;
    for run_index in 1..=config.repeats {
        if !run_once(&teec, &mut coverage, &input, run_index, &mut stats)? {
            status = FAILED_STATUS;
        }
    }
    print_opcode_totals(&stats);
    println!("FUZZ_REPLAY_DONE runs={} status={status}", config.repeats);
    if status != 0 {
        return Err(format!("one or more replay invocations failed (status={status})").into());
    }
    Ok(())
}
