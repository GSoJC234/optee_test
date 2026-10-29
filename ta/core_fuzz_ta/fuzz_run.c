// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Jaehun Lee
 */

#include <core_fuzz_ta.h>
#include <crypto_ops.h>
#include <fuzz_run.h>
#include <pta_core_fuzz_cov.h>
#include <tee_internal_api.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static uint16_t read_u16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static void write_u32(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)value;
	p[1] = (uint8_t)(value >> 8);
	p[2] = (uint8_t)(value >> 16);
	p[3] = (uint8_t)(value >> 24);
}

static TEE_Result check_params(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t expected_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE);

	if (param_types != expected_types ||
	    !params[0].memref.buffer ||
	    params[0].memref.size > CORE_FUZZ_TA_MAX_INPUT ||
	    params[0].memref.size < CORE_FUZZ_TA_INPUT_HEADER_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[2].memref.size < PTA_CORE_FUZZ_COV_MAP_SIZE) {
		params[2].memref.size = PTA_CORE_FUZZ_COV_MAP_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}
	if (!params[2].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!params[1].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

static bool valid_input(const uint8_t *input, size_t size)
{
	size_t offset = CORE_FUZZ_TA_INPUT_HEADER_SIZE;
	uint8_t count = 0;
	uint8_t i = 0;

	if (size < CORE_FUZZ_TA_INPUT_HEADER_SIZE)
		return false;
	count = input[5];
	if (count > CORE_FUZZ_TA_MAX_OPS)
		return false;

	for (i = 0; i < count; i++) {
		uint16_t data_len = 0;

		if (size - offset < CORE_FUZZ_TA_OP_HEADER_SIZE)
			return false;
		if (input[offset + 1] >= CORE_FUZZ_TA_SLOTS)
			return false;
		data_len = read_u16(input + offset + 3);
		if (data_len > size - offset - CORE_FUZZ_TA_OP_HEADER_SIZE)
			return false;
		offset += CORE_FUZZ_TA_OP_HEADER_SIZE + data_len;
	}

	return true;
}

static TEE_Result start_coverage(TEE_TASessionHandle *session)
{
	const TEE_UUID uuid = PTA_CORE_FUZZ_COV_UUID;
	TEE_Result result = TEE_SUCCESS;

	*session = TEE_HANDLE_NULL;

	result = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE,
				   0, NULL, session, NULL);
	if (result != TEE_SUCCESS)
		goto out;
	result = TEE_InvokeTACommand(*session, TEE_TIMEOUT_INFINITE,
				     PTA_CORE_FUZZ_COV_BEGIN, 0, NULL, NULL);
	if (result == TEE_SUCCESS)
		return result;

out:
	if (*session != TEE_HANDLE_NULL) {
		TEE_CloseTASession(*session);
		*session = TEE_HANDLE_NULL;
	}
	return result;
}

static TEE_Result end_coverage(TEE_TASessionHandle session,
			       TEE_Param params[4])
{
	TEE_Param coverage_params[4] = { 0 };
	TEE_Result result = TEE_SUCCESS;

	coverage_params[0].memref.buffer = params[2].memref.buffer;
	coverage_params[0].memref.size = params[2].memref.size;
	result = TEE_InvokeTACommand(session, TEE_TIMEOUT_INFINITE,
		PTA_CORE_FUZZ_COV_END,
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE), coverage_params, NULL);
	params[2].memref.size = coverage_params[0].memref.size;
	TEE_CloseTASession(session);
	return result;
}

TEE_Result fuzz_run(uint32_t param_types, TEE_Param params[4])
{
	TEE_TASessionHandle coverage_session = TEE_HANDLE_NULL;
	uint8_t *input = NULL;
	uint8_t *output = NULL;
	struct fuzz_context ctx = { };
	size_t input_size = 0;
	size_t output_size = 0;
	size_t output_capacity = 0;
	size_t offset = CORE_FUZZ_TA_INPUT_HEADER_SIZE;
	uint8_t count = 0;
	uint8_t i = 0;
	TEE_Result result = TEE_SUCCESS;

	result = check_params(param_types, params);
	if (result != TEE_SUCCESS)
		return result;
	fuzz_context_init(&ctx);

	input_size = params[0].memref.size;
	input = TEE_Malloc(input_size, TEE_MALLOC_FILL_ZERO);
	if (!input)
		return TEE_ERROR_OUT_OF_MEMORY;
	/* REE shared memory may change during an invocation. Parse a TA-owned copy. */
	TEE_MemMove(input, params[0].memref.buffer, input_size);
	if (!valid_input(input, input_size)) {
		result = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	count = input[5];

	output_capacity = params[1].memref.size;
	output_size = CORE_FUZZ_TA_OUTPUT_HEADER_SIZE +
		(size_t)count * CORE_FUZZ_TA_RESULT_SIZE;
	params[1].memref.size = output_size;
	if (output_size > CORE_FUZZ_TA_MAX_OUTPUT) {
		result = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	if (output_capacity < output_size) {
		result = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}
	output = TEE_Malloc(output_size, TEE_MALLOC_FILL_ZERO);
	if (!output) {
		result = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	TEE_MemMove(output, CORE_FUZZ_TA_OUTPUT_MAGIC, 4);
	output[4] = CORE_FUZZ_TA_VERSION;
	output[5] = count;

	result = start_coverage(&coverage_session);
	if (result != TEE_SUCCESS)
		goto out;

	for (i = 0; i < count; i++) {
		struct fuzz_op op = {
			.opcode = input[offset],
			.slot = input[offset + 1],
			.selector = input[offset + 2],
			.data_len = read_u16(input + offset + 3),
			.aux = read_u16(input + offset + 5),
			.data = input + offset + CORE_FUZZ_TA_OP_HEADER_SIZE,
		};
		uint8_t *record = output + CORE_FUZZ_TA_OUTPUT_HEADER_SIZE +
			(size_t)i * CORE_FUZZ_TA_RESULT_SIZE;
		TEE_Result step = TEE_SUCCESS;

		record[4] = op.opcode;
		record[5] = op.slot;
		step = crypto_execute(&ctx, &op, record);
		write_u32(record, step);
		offset += CORE_FUZZ_TA_OP_HEADER_SIZE + op.data_len;
	}

	TEE_MemMove(params[1].memref.buffer, output, output_size);

out:
	crypto_cleanup(&ctx);
	if (coverage_session != TEE_HANDLE_NULL) {
		TEE_Result coverage_result = end_coverage(coverage_session,
								params);

		if (result == TEE_SUCCESS)
			result = coverage_result;
	}
	TEE_Free(output);
	TEE_Free(input);
	return result;
}
