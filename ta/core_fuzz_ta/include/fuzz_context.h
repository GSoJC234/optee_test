/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Jaehun Lee
 */
#ifndef FUZZ_CONTEXT_H
#define FUZZ_CONTEXT_H

#include <core_fuzz_ta.h>
#include <stdint.h>

struct fuzz_context {
	uint32_t crypto_state_handles[CORE_FUZZ_TA_SLOTS];
	uint32_t crypto_object_handles[CORE_FUZZ_TA_SLOTS];
	/* Object slot for each state; UINT8_MAX means no key. */
	uint8_t state_key_slots[CORE_FUZZ_TA_SLOTS];
	/* Full asymmetric result for a later VERIFY operation. */
	uint8_t asymm_result[CORE_FUZZ_TA_TEMP_OUTPUT_SIZE];
	uint16_t asymm_result_len;
};

static inline void fuzz_context_init(struct fuzz_context *ctx)
{
	uint32_t i = 0;

	*ctx = (struct fuzz_context){ 0 };
	for (i = 0; i < CORE_FUZZ_TA_SLOTS; i++)
		ctx->state_key_slots[i] = UINT8_MAX;
}

#endif /* FUZZ_CONTEXT_H */
