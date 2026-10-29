// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! The secure-world coverage map shared by the C shim and LibAFL.

use std::ptr::NonNull;

use libafl::observers::StdMapObserver;

include!(concat!(env!("OUT_DIR"), "/core_fuzz_cov.rs"));

/// Name of the LibAFL map observer; it is part of the corpus metadata.
const OBSERVER_NAME: &str = "optee_secure_core_edges";

/// The coverage buffer filled by the coverage PTA through the TA.
///
/// Both the C shim and LibAFL's [`StdMapObserver`] need a stable address for
/// the whole campaign, so the buffer is allocated once and deliberately
/// leaked. Rust code reaches it only through this handle:
/// [`TeecContext::run`] takes `&mut CoverageMap` while C writes to it and
/// [`CoverageMap::as_slice`] takes `&self`, so the borrow checker keeps the
/// two apart.
///
/// [`TeecContext::run`]: super::teec::TeecContext::run
#[derive(Debug)]
pub(crate) struct CoverageMap {
    ptr: NonNull<u8>,
}

impl CoverageMap {
    pub(crate) fn new() -> Self {
        let map: &'static mut [u8] = Box::leak(vec![0; COVERAGE_SIZE].into_boxed_slice());
        Self {
            ptr: NonNull::from(map).cast(),
        }
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub(crate) const fn len(&self) -> usize {
        COVERAGE_SIZE
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: the allocation holds `COVERAGE_SIZE` initialized bytes and
        // is never freed. `&self` excludes `TeecContext::run`, the only writer
        // besides LibAFL, and the observer never runs concurrently with us.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), COVERAGE_SIZE) }
    }

    /// Discards bytes from an invocation that returned no valid coverage.
    pub(crate) fn clear(&mut self) {
        // SAFETY: `self.ptr` owns a leaked allocation of `COVERAGE_SIZE` bytes
        // and no observer callback runs while the harness executes.
        unsafe { std::ptr::write_bytes(self.ptr.as_ptr(), 0, COVERAGE_SIZE) };
    }

    /// Creates the LibAFL observer over this map.
    pub(crate) fn observer(&mut self) -> StdMapObserver<'static, u8, false> {
        // SAFETY: the buffer is leaked, so it outlives the observer, and holds
        // `COVERAGE_SIZE` bytes. The observer keeps only the raw address and
        // forms slices inside its callbacks; the campaign is single-threaded
        // and those callbacks never overlap a `TeecContext::run` call.
        unsafe { StdMapObserver::from_mut_ptr(OBSERVER_NAME, self.as_mut_ptr(), COVERAGE_SIZE) }
    }
}
