// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Jaehun Lee
 *
 * libteec client used by the Rust runner (src/runner/teec.rs). It keeps one
 * TA session open across inputs and reopens it after the TA dies.
 */

#include <core_fuzz_ta.h>
#include <pta_core_fuzz_cov.h>
#include <tee_client_api.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "teec_shim.h"

_Static_assert(CORE_FUZZ_TA_MAX_OUTPUT == CORE_FUZZ_TA_RUST_MAX_OUTPUT,
	       "Rust and TA response capacities differ");
_Static_assert(PTA_CORE_FUZZ_COV_MAP_SIZE == CORE_FUZZ_TA_RUST_COVERAGE_SIZE,
	       "Rust and PTA coverage map sizes differ");
/* src/runner/teec.rs compares invocation results against these values. */
_Static_assert(TEEC_SUCCESS == 0x00000000, "TEEC_SUCCESS changed");
_Static_assert(TEEC_ERROR_TARGET_DEAD == 0xFFFF3024,
	       "TEEC_ERROR_TARGET_DEAD changed");

struct core_fuzz_teec_context {
	TEEC_Context context;
	TEEC_Session session;
	bool session_open;
};

static TEEC_Result open_session(struct core_fuzz_teec_context *context)
{
	const TEEC_UUID uuid = CORE_FUZZ_TA_UUID;
	uint32_t origin = 0;
	TEEC_Result result = TEEC_SUCCESS;

	memset(&context->session, 0, sizeof(context->session));
	result = TEEC_OpenSession(&context->context, &context->session, &uuid,
				  TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (result == TEEC_SUCCESS)
		context->session_open = true;

	return result;
}

static void close_session(struct core_fuzz_teec_context *context)
{
	if (!context->session_open)
		return;

	TEEC_CloseSession(&context->session);
	memset(&context->session, 0, sizeof(context->session));
	context->session_open = false;
}

uint32_t core_fuzz_teec_init(void **context_out)
{
	struct core_fuzz_teec_context *context = NULL;
	TEEC_Result result = TEEC_SUCCESS;

	if (!context_out)
		return TEEC_ERROR_BAD_PARAMETERS;
	*context_out = NULL;

	context = calloc(1, sizeof(*context));
	if (!context)
		return TEEC_ERROR_OUT_OF_MEMORY;

	result = TEEC_InitializeContext(NULL, &context->context);
	if (result != TEEC_SUCCESS) {
		free(context);
		return result;
	}

	result = open_session(context);
	if (result != TEEC_SUCCESS) {
		TEEC_FinalizeContext(&context->context);
		free(context);
		return result;
	}

	*context_out = context;
	return TEEC_SUCCESS;
}

uint32_t core_fuzz_teec_run(void *opaque, const uint8_t *input,
			    size_t input_size, uint8_t *response_out,
			    size_t response_capacity, size_t *response_size,
			    uint8_t *coverage, size_t coverage_capacity,
			    size_t *coverage_size)
{
	struct core_fuzz_teec_context *context = opaque;
	TEEC_Operation operation = { };
	uint8_t response[CORE_FUZZ_TA_MAX_OUTPUT] = { };
	TEEC_Result result = TEEC_SUCCESS;
	uint32_t origin = 0;

	if (response_size)
		*response_size = 0;
	if (coverage_size)
		*coverage_size = 0;
	if (!context || !input || !response_out || !response_size ||
	    !coverage || !coverage_size || input_size > CORE_FUZZ_TA_MAX_INPUT ||
	    response_capacity < CORE_FUZZ_TA_MAX_OUTPUT ||
	    coverage_capacity < PTA_CORE_FUZZ_COV_MAP_SIZE)
		return TEEC_ERROR_BAD_PARAMETERS;

	memset(coverage, 0, coverage_capacity);
	if (!context->session_open) {
		result = open_session(context);
		if (result != TEEC_SUCCESS)
			return result;
	}

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						TEEC_MEMREF_TEMP_OUTPUT,
						TEEC_MEMREF_TEMP_OUTPUT,
						TEEC_NONE);
	operation.params[0].tmpref.buffer = (void *)input;
	operation.params[0].tmpref.size = input_size;
	operation.params[1].tmpref.buffer = response;
	operation.params[1].tmpref.size = sizeof(response);
	operation.params[2].tmpref.buffer = coverage;
	operation.params[2].tmpref.size = coverage_capacity;

	result = TEEC_InvokeCommand(&context->session, CORE_FUZZ_TA_CMD_RUN,
				    &operation, &origin);
	if (result == TEEC_SUCCESS) {
		if (operation.params[1].tmpref.size > response_capacity) {
			result = TEEC_ERROR_SHORT_BUFFER;
		} else {
			memcpy(response_out, operation.params[1].tmpref.buffer,
			       operation.params[1].tmpref.size);
			*response_size = operation.params[1].tmpref.size;
			*coverage_size = operation.params[2].tmpref.size;
		}
	}

	/* Recover for the next input after this one records the target crash */
	if (result == TEEC_ERROR_TARGET_DEAD)
		close_session(context);

	return result;
}

void core_fuzz_teec_fini(void *opaque)
{
	struct core_fuzz_teec_context *context = opaque;

	if (!context)
		return;

	close_session(context);
	TEEC_FinalizeContext(&context->context);
	free(context);
}
