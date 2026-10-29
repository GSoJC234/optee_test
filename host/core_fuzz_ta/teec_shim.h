/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Jaehun Lee
 *
 * libteec client for the Rust runner. src/runner/teec.rs declares the same
 * functions in its `extern "C"` block; keep the two in sync.
 */

#ifndef TEEC_SHIM_H
#define TEEC_SHIM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Initializes a TEEC context and opens a session to core_fuzz_ta. On success
 * stores an opaque handle in *context_out.
 */
uint32_t core_fuzz_teec_init(void **context_out);

/*
 * Runs one input through CORE_FUZZ_TA_CMD_RUN on the retained session. After
 * TEEC_ERROR_TARGET_DEAD the session is closed and reopened on the next call.
 */
uint32_t core_fuzz_teec_run(void *opaque, const uint8_t *input,
			    size_t input_size, uint8_t *response_out,
			    size_t response_capacity, size_t *response_size,
			    uint8_t *coverage, size_t coverage_capacity,
			    size_t *coverage_size);

/* Closes the session and finalizes the context; accepts NULL */
void core_fuzz_teec_fini(void *opaque);

#endif /* TEEC_SHIM_H */
