// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Portable pieces of the `core_fuzz_ta` LibAFL runner.
//!
//! This library holds everything that does not need libteec or a TEE, so it
//! can be tested on any development host: the FZP2 input format
//! ([`program`]), the structure-aware LibAFL mutator ([`mutator`]), the FZR2
//! response decoder ([`response`]), the command line ([`cli`]), campaign
//! statistics ([`stats`]) and output files ([`output`]). The QEMU-guest
//! binary in `src/main.rs` adds the TEEC client and the campaign loops.
//!
//! The wire format itself is defined by
//! `ta/core_fuzz_ta/include/core_fuzz_ta.h`; [`protocol`] is generated from it.

#![warn(missing_docs)]

pub mod algorithms;
pub mod cli;
mod crypto_mutator;
pub mod mutator;
pub mod output;
pub mod program;
pub mod protocol;
pub mod response;
pub mod stats;
