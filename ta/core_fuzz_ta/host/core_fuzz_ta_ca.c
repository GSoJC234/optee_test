// SPDX-License-Identifier: BSD-2-Clause
#include <core_fuzz_ta.h>
#include <pta_core_fuzz_cov.h>
#include <tee_client_api.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t read_u16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
		((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int print_response(const uint8_t *buffer, size_t size)
{
	uint8_t count = 0;
	uint8_t i = 0;

	if (size < CORE_FUZZ_TA_OUTPUT_HEADER_SIZE ||
	    memcmp(buffer, "FZR2", 4) ||
	    buffer[4] != CORE_FUZZ_TA_VERSION ||
	    buffer[5] > CORE_FUZZ_TA_MAX_OPS || buffer[6] || buffer[7]) {
		fprintf(stderr, "invalid TA response header\n");
		return -1;
	}
	count = buffer[5];
	if (size != CORE_FUZZ_TA_OUTPUT_HEADER_SIZE +
	    (size_t)count * CORE_FUZZ_TA_RESULT_SIZE) {
		fprintf(stderr, "invalid TA response length: %zu\n", size);
		return -1;
	}

	for (i = 0; i < count; i++) {
		const uint8_t *record = buffer + CORE_FUZZ_TA_OUTPUT_HEADER_SIZE +
			(size_t)i * CORE_FUZZ_TA_RESULT_SIZE;
		const uint32_t status = read_u32(record);
		const uint16_t digest_len = read_u16(record + 6);
		uint16_t j = 0;

		printf("step=%u opcode=%u slot=%u status=0x%08" PRIx32
		       " digest_len=%u", i, record[4], record[5], status,
		       digest_len);
		if (record[4] == CORE_FUZZ_TA_FINAL && status == TEEC_SUCCESS &&
		    digest_len <= 32) {
			printf(" digest=");
			for (j = 0; j < digest_len; j++)
				printf("%02x", record[8 + j]);
		}
		putchar('\n');
	}
	return 0;
}

static void print_usage(const char *program)
{
	fprintf(stderr,
		"usage: %s INPUT_FILE [REPEAT_COUNT]\n"
		"       %s --reproduce INPUT_FILE [TARGET_INDEX]\n",
		program, program);
}

int main(int argc, char *argv[])
{
	const TEEC_UUID uuid = CORE_FUZZ_TA_UUID;
	uint8_t input[CORE_FUZZ_TA_MAX_INPUT + 1];
	uint8_t output[CORE_FUZZ_TA_MAX_OUTPUT];
	uint8_t coverage[PTA_CORE_FUZZ_COV_MAP_SIZE];
	TEEC_Context context = { 0 };
	FILE *file = NULL;
	const char *input_path = NULL;
	char *end = NULL;
	unsigned long repeat = 1;
	long parsed_target = 0;
	size_t input_size = 0;
	TEEC_Result result = TEEC_SUCCESS;
	uint32_t origin = 0;
	unsigned long i = 0;
	int target_index = -1;
	int reproduce_mode = 0;
	int exit_status = 0;

	if (argc >= 2 && !strcmp(argv[1], "--reproduce")) {
		if (argc < 3 || argc > 4) {
			print_usage(argv[0]);
			return 2;
		}
		reproduce_mode = 1;
		input_path = argv[2];
		if (argc == 4) {
			errno = 0;
			parsed_target = strtol(argv[3], &end, 10);
			if (errno || !end || *end || parsed_target < 0 ||
			    parsed_target >= CORE_FUZZ_TA_MAX_OPS) {
				fprintf(stderr, "TARGET_INDEX must be 0..%u\n",
					CORE_FUZZ_TA_MAX_OPS - 1);
				return 2;
			}
			target_index = (int)parsed_target;
		}
	} else {
		if (argc < 2 || argc > 3) {
			print_usage(argv[0]);
			return 2;
		}
		input_path = argv[1];
		if (argc == 3) {
			errno = 0;
			repeat = strtoul(argv[2], &end, 10);
			if (errno || !end || *end || !repeat || repeat > 10000) {
				fprintf(stderr, "REPEAT_COUNT must be 1..10000\n");
				return 2;
			}
		}
	}
	file = fopen(input_path, "rb");
	if (!file) {
		perror(input_path);
		return 2;
	}
	input_size = fread(input, 1, sizeof(input), file);
	if (ferror(file) || input_size > CORE_FUZZ_TA_MAX_INPUT) {
		fprintf(stderr, "input read failed or exceeds %u bytes\n",
			CORE_FUZZ_TA_MAX_INPUT);
		fclose(file);
		return 2;
	}
	fclose(file);

	result = TEEC_InitializeContext(NULL, &context);
	if (result != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_InitializeContext: 0x%08" PRIx32 "\n",
			(uint32_t)result);
		return 2;
	}
	for (i = 0; i < repeat; i++) {
		TEEC_Session session = { 0 };
		TEEC_Operation operation = { 0 };

		origin = 0;
		result = TEEC_OpenSession(&context, &session, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
		if (result != TEEC_SUCCESS) {
			fprintf(stderr, "run=%lu open=0x%08" PRIx32
				" origin=%" PRIu32 "\n", i + 1,
				(uint32_t)result, origin);
			exit_status = 2;
			break;
		}
		memset(output, 0, sizeof(output));
		if (reproduce_mode) {
			memset(coverage, 0, sizeof(coverage));
			operation.paramTypes = TEEC_PARAM_TYPES(
				TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
				TEEC_MEMREF_TEMP_OUTPUT,
				target_index < 0 ? TEEC_NONE : TEEC_VALUE_INPUT);
			operation.params[2].tmpref.buffer = coverage;
			operation.params[2].tmpref.size = sizeof(coverage);
			if (target_index >= 0)
				operation.params[3].value.a =
					(uint32_t)target_index;
		} else {
			operation.paramTypes = TEEC_PARAM_TYPES(
				TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
				TEEC_NONE, TEEC_NONE);
		}
		operation.params[0].tmpref.buffer = input;
		operation.params[0].tmpref.size = input_size;
		operation.params[1].tmpref.buffer = output;
		operation.params[1].tmpref.size = sizeof(output);
		origin = 0;
		result = TEEC_InvokeCommand(&session, CORE_FUZZ_TA_CMD_RUN,
			&operation, &origin);
		printf("run=%lu invoke=0x%08" PRIx32 " origin=%" PRIu32,
			i + 1, (uint32_t)result, origin);
		if (result == TEEC_ERROR_TARGET_DEAD)
			printf(" classification=TA_TARGET_DEAD");
		if (reproduce_mode)
			printf(" coverage_scope=%s target_index=%d coverage_bytes=%zu",
			       target_index < 0 ? "whole" : "target", target_index,
			       operation.params[2].tmpref.size);
		putchar('\n');
		if (result == TEEC_SUCCESS) {
			if (reproduce_mode &&
			    operation.params[2].tmpref.size != sizeof(coverage)) {
				fprintf(stderr, "invalid coverage map length: %zu\n",
					operation.params[2].tmpref.size);
				exit_status = 2;
			}
			if (print_response(output,
				operation.params[1].tmpref.size))
				exit_status = 2;
		} else {
			exit_status = 2;
		}
		TEEC_CloseSession(&session);
	}
	TEEC_FinalizeContext(&context);
	return exit_status;
}
