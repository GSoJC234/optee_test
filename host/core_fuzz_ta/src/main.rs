// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! `core-fuzz-ta-libafl`: LibAFL runner for `ta/core_fuzz_ta`, executed in the
//! OP-TEE QEMU normal-world guest.
//!
//! See `README.md` for the invocation forms and output format.

mod runner;

use std::process::ExitCode;

use core_fuzz_ta_libafl::cli;

/// Exit status for runtime errors; usage errors use clap's status, also 2.
const ERROR_STATUS: u8 = 2;

fn main() -> ExitCode {
    let mode = cli::parse(std::env::args_os()).unwrap_or_else(|error| error.exit());
    match runner::run(&mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FUZZ_ERROR={error}");
            ExitCode::from(ERROR_STATUS)
        }
    }
}
