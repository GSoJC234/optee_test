// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Safe wrapper around `teec_shim.c`, which owns the libteec structures.

use std::{ffi::c_void, io, ptr::NonNull};

use super::coverage::CoverageMap;

/// `TEEC_SUCCESS` from `tee_client_api.h`.
pub(crate) const TEEC_SUCCESS: u32 = 0;
/// Expected for deliberately malformed command streams.
pub(crate) const TEEC_ERROR_BAD_PARAMETERS: u32 = 0xffff_0006;
/// `TEEC_ERROR_TARGET_DEAD` from `tee_client_api.h`; `teec_shim.c` asserts
/// that the header agrees.
pub(crate) const TEEC_ERROR_TARGET_DEAD: u32 = 0xffff_3024;

// Mirrors teec_shim.h.
unsafe extern "C" {
    fn core_fuzz_teec_init(context_out: *mut *mut c_void) -> u32;
    fn core_fuzz_teec_run(
        context: *mut c_void,
        input: *const u8,
        input_size: usize,
        response: *mut u8,
        response_capacity: usize,
        response_size: *mut usize,
        coverage: *mut u8,
        coverage_capacity: usize,
        coverage_size: *mut usize,
    ) -> u32;
    fn core_fuzz_teec_fini(context: *mut c_void);
}

/// Outcome of one `CORE_FUZZ_TA_CMD_RUN` invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Invocation {
    /// `TEEC_Result` of the command invocation (or session recovery).
    pub(crate) result: u32,
    /// Bytes written to the response buffer.
    pub(crate) response_len: usize,
    /// Bytes of coverage map returned by the TA.
    pub(crate) coverage_len: usize,
}

impl Invocation {
    pub(crate) fn succeeded(self) -> bool {
        self.result == TEEC_SUCCESS
    }

    pub(crate) fn target_dead(self) -> bool {
        self.result == TEEC_ERROR_TARGET_DEAD
    }

    pub(crate) fn input_rejected(self) -> bool {
        self.result == TEEC_ERROR_BAD_PARAMETERS
    }
}

/// An initialized `TEEC_Context` with a persistent TA session, finalized on drop.
///
/// The raw pointer makes this type `!Send` and `!Sync`, which matches how
/// the runner uses libteec: from one thread only.
#[derive(Debug)]
pub(crate) struct TeecContext {
    raw: NonNull<c_void>,
}

impl TeecContext {
    pub(crate) fn new() -> io::Result<Self> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: `raw` is a valid out-pointer; the shim stores a context
        // pointer there only on success.
        let result = unsafe { core_fuzz_teec_init(&raw mut raw) };
        if result != TEEC_SUCCESS {
            return Err(io::Error::other(format!(
                "TEEC context initialization failed: 0x{result:08x}"
            )));
        }
        let raw = NonNull::new(raw)
            .ok_or_else(|| io::Error::other("TEEC shim returned a null context"))?;
        Ok(Self { raw })
    }

    /// Invokes the TA once on the session retained by this context.
    ///
    /// The session stays open between inputs. If the TA dies, the shim closes
    /// the dead session and opens a replacement before the next invocation.
    /// The TA's response is written to `response` and the secure-world
    /// coverage map to `coverage`.
    pub(crate) fn run(
        &self,
        input: &[u8],
        response: &mut [u8],
        coverage: &mut CoverageMap,
    ) -> Invocation {
        let mut response_len = 0;
        let mut coverage_len = 0;
        // SAFETY: `self.raw` came from `core_fuzz_teec_init` and is still
        // live. `input` and `response` are valid for their lengths and do not
        // overlap. `coverage` is borrowed exclusively, so no Rust reference
        // into the map is live; the LibAFL observer only touches the map from
        // its pre/post-execution callbacks, which never run during this
        // synchronous call. The shim does not keep any pointer after it
        // returns.
        let result = unsafe {
            core_fuzz_teec_run(
                self.raw.as_ptr(),
                input.as_ptr(),
                input.len(),
                response.as_mut_ptr(),
                response.len(),
                &raw mut response_len,
                coverage.as_mut_ptr(),
                coverage.len(),
                &raw mut coverage_len,
            )
        };
        Invocation {
            result,
            response_len,
            coverage_len,
        }
    }
}

impl Drop for TeecContext {
    fn drop(&mut self) {
        // SAFETY: the context was initialized by `core_fuzz_teec_init` and is
        // finalized exactly once, here.
        unsafe { core_fuzz_teec_fini(self.raw.as_ptr()) };
    }
}
