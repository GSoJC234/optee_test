// SPDX-License-Identifier: BSD-2-Clause
#include <core_fuzz_ta.h>
#include <fuzz_context.h>
#include <pta_core_fuzz_cov.h>
#include <tee_internal_api.h>
#include <tee_api_defines_extensions.h>
#include <utee_syscalls.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static uint16_t read_u16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static void write_u16(uint8_t *p, uint16_t value)
{
	p[0] = (uint8_t)value;
	p[1] = (uint8_t)(value >> 8);
}

static void write_u32(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)value;
	p[1] = (uint8_t)(value >> 8);
	p[2] = (uint8_t)(value >> 16);
	p[3] = (uint8_t)(value >> 24);
}

static void write_result_length(uint8_t *record, uint64_t length)
{
	write_u16(record + 6, length > UINT16_MAX ? UINT16_MAX : length);
}

static void copy_result_prefix(uint8_t *record, const uint8_t *value,
			       uint64_t length)
{
	TEE_MemMove(record + 8, value,
		    length > CORE_FUZZ_TA_RESULT_DATA_SIZE ?
		    CORE_FUZZ_TA_RESULT_DATA_SIZE : length);
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
	return result;
}

/* Check only the bounds needed to decode and execute the operation stream. */
static bool valid_input(const uint8_t *input, size_t size, uint8_t *count)
{
	size_t offset = CORE_FUZZ_TA_INPUT_HEADER_SIZE;
	uint8_t i = 0;

	if (size < CORE_FUZZ_TA_INPUT_HEADER_SIZE ||
	    input[5] > CORE_FUZZ_TA_MAX_OPS)
		return false;

	*count = input[5];
	for (i = 0; i < *count; i++) {
		uint8_t opcode = 0;
		uint16_t data_len = 0;
		uint16_t aux = 0;

		if (size - offset < CORE_FUZZ_TA_OP_HEADER_SIZE)
			return false;
		opcode = input[offset];
		data_len = read_u16(input + offset + 3);
		aux = read_u16(input + offset + 5);
		if (input[offset + 1] >= CORE_FUZZ_TA_SLOTS ||
		    data_len > size - offset - CORE_FUZZ_TA_OP_HEADER_SIZE)
			return false;
		if (opcode == CORE_FUZZ_TA_FINAL && aux > 64)
			return false;
		offset += CORE_FUZZ_TA_OP_HEADER_SIZE + data_len;
	}

	return true;
}

static TEE_Result run(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t legacy_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);
	const uint32_t coverage_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE);
	const uint32_t target_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_VALUE_INPUT);
	const TEE_UUID coverage_uuid = PTA_CORE_FUZZ_COV_UUID;
	TEE_TASessionHandle coverage_session = TEE_HANDLE_NULL;
	bool target_coverage = param_types == target_types;
	bool collect_coverage = param_types == coverage_types || target_coverage;
	bool coverage_started = false;
	uint8_t *input = NULL;
	uint8_t *output = NULL;
	struct fuzz_context ctx;
	size_t input_size = 0;
	size_t output_size = 0;
	size_t output_capacity = params[1].memref.size;
	size_t offset = CORE_FUZZ_TA_INPUT_HEADER_SIZE;
	uint8_t count = 0;
	uint8_t i = 0;
	uint32_t target_index = 0;
	TEE_Result result = TEE_SUCCESS;

	fuzz_context_init(&ctx);

	if ((param_types != legacy_types && !collect_coverage) ||
	    !params[0].memref.buffer ||
	    params[0].memref.size > CORE_FUZZ_TA_MAX_INPUT ||
	    params[0].memref.size < CORE_FUZZ_TA_INPUT_HEADER_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	if (collect_coverage) {
		if (params[2].memref.size < PTA_CORE_FUZZ_COV_MAP_SIZE) {
			params[2].memref.size = PTA_CORE_FUZZ_COV_MAP_SIZE;
			return TEE_ERROR_SHORT_BUFFER;
		}
		if (!params[2].memref.buffer)
			return TEE_ERROR_BAD_PARAMETERS;
	}

	input_size = params[0].memref.size;
	input = TEE_Malloc(input_size, TEE_MALLOC_FILL_ZERO);
	if (!input)
		return TEE_ERROR_OUT_OF_MEMORY;
	/* REE shared memory may change during an invocation. Parse a TA-owned copy. */
	TEE_MemMove(input, params[0].memref.buffer, input_size);
	if (!valid_input(input, input_size, &count)) {
		result = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	if (target_coverage) {
		target_index = params[3].value.a;
		if (target_index >= count || params[3].value.b) {
			result = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}
	}

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
	if (!params[1].memref.buffer) {
		result = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	output = TEE_Malloc(output_size, TEE_MALLOC_FILL_ZERO);
	if (!output) {
		result = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	output[0] = 'F';
	output[1] = 'Z';
	output[2] = 'R';
	output[3] = '2';
	output[4] = CORE_FUZZ_TA_VERSION;
	output[5] = count;

	if (collect_coverage) {
		result = TEE_OpenTASession(&coverage_uuid, TEE_TIMEOUT_INFINITE,
			0, NULL, &coverage_session, NULL);
		if (result != TEE_SUCCESS)
			goto out;
		if (!target_coverage) {
			result = TEE_InvokeTACommand(coverage_session,
				TEE_TIMEOUT_INFINITE, PTA_CORE_FUZZ_COV_BEGIN,
				0, NULL, NULL);
			if (result != TEE_SUCCESS)
				goto out;
			coverage_started = true;
		}
	}

	for (i = 0; i < count; i++) {
		const uint8_t opcode = input[offset];
		const uint8_t slot = input[offset + 1];
		const uint8_t selector = input[offset + 2];
		const uint16_t data_len = read_u16(input + offset + 3);
		const uint16_t aux = read_u16(input + offset + 5);
		const uint8_t *data = input + offset + CORE_FUZZ_TA_OP_HEADER_SIZE;
		uint8_t *record = output + CORE_FUZZ_TA_OUTPUT_HEADER_SIZE +
			(size_t)i * CORE_FUZZ_TA_RESULT_SIZE;
		TEE_Result step = TEE_SUCCESS;

		if (target_coverage && i == target_index) {
			result = TEE_InvokeTACommand(coverage_session,
				TEE_TIMEOUT_INFINITE, PTA_CORE_FUZZ_COV_BEGIN,
				0, NULL, NULL);
			if (result != TEE_SUCCESS)
				goto out;
			coverage_started = true;
		}
		record[4] = opcode;
		record[5] = slot;
		switch (opcode) {
		case CORE_FUZZ_TA_ALLOC: {
			unsigned long algo = TEE_ALG_SHA256;
			unsigned long mode = TEE_MODE_DIGEST;
			unsigned long key = 0;

			switch (selector) {
			case 0:
				break;
			case 1:
				algo = TEE_ALG_SHA512;
				break;
			case 2:
				algo = TEE_ALG_HMAC_SHA256;
				mode = TEE_MODE_MAC;
				break;
			case 3:
			case 4:
				algo = TEE_ALG_AES_CTR;
				mode = selector == 3 ? TEE_MODE_ENCRYPT :
					TEE_MODE_DECRYPT;
				break;
			case 5:
			case 6:
				algo = TEE_ALG_AES_GCM;
				mode = selector == 5 ? TEE_MODE_ENCRYPT :
					TEE_MODE_DECRYPT;
				break;
			case 7:
				algo = TEE_ALG_HKDF;
				mode = TEE_MODE_DERIVE;
				break;
			case 8:
			case 9:
				algo = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
				mode = selector == 8 ? TEE_MODE_SIGN :
					TEE_MODE_VERIFY;
				break;
			case 10:
			case 11:
				algo = TEE_ALG_RSAES_PKCS1_V1_5;
				mode = selector == 10 ? TEE_MODE_ENCRYPT :
					TEE_MODE_DECRYPT;
				break;
			case 12:
			case 13:
				algo = TEE_ALG_AES_CCM;
				mode = selector == 12 ? TEE_MODE_ENCRYPT :
					TEE_MODE_DECRYPT;
				break;
			case 14:
			case 15:
				algo = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;
				mode = selector == 14 ? TEE_MODE_SIGN :
					TEE_MODE_VERIFY;
				break;
			case 16:
			case 17:
				algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256;
				mode = selector == 16 ? TEE_MODE_ENCRYPT :
					TEE_MODE_DECRYPT;
				break;
			default:
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			if (step != TEE_SUCCESS)
				break;
			/* Every selected keyed algorithm uses exactly one key. */
			if (selector >= 2) {
				if (aux >= CORE_FUZZ_TA_SLOTS) {
					step = TEE_ERROR_BAD_PARAMETERS;
					break;
				}
				key = ctx.crypto_object_handles[aux];
			}
			if (ctx.crypto_state_handles[slot]) {
				step = TEE_ERROR_BAD_STATE;
			} else {
				uint32_t handle = 0;

				step = _utee_cryp_state_alloc(algo, mode, key, 0,
							     &handle);
				if (step == TEE_SUCCESS) {
					ctx.crypto_state_handles[slot] = handle;
					if (selector >= 2)
						ctx.state_key_slots[slot] = (uint8_t)aux;
				} else if (handle)
					_utee_cryp_state_free(handle);
			}
			break;
		}
		case CORE_FUZZ_TA_INIT:
			step = _utee_hash_init(ctx.crypto_state_handles[slot],
					       NULL, 0);
			break;
		case CORE_FUZZ_TA_UPDATE:
			step = _utee_hash_update(ctx.crypto_state_handles[slot],
						 data, data_len);
			break;
		case CORE_FUZZ_TA_FINAL: {
			uint8_t digest[64] = { 0 };
			uint64_t digest_len = aux;

			step = _utee_hash_final(ctx.crypto_state_handles[slot],
						data, data_len, digest,
						&digest_len);
			if (digest_len > UINT16_MAX)
				digest_len = UINT16_MAX;
			write_result_length(record, digest_len);
			if (step == TEE_SUCCESS)
				copy_result_prefix(record, digest, digest_len);
			break;
		}
		case CORE_FUZZ_TA_FREE:
			if (!ctx.crypto_state_handles[slot]) {
				step = TEE_ERROR_BAD_STATE;
			} else {
				step = _utee_cryp_state_free(
					ctx.crypto_state_handles[slot]);
				if (step == TEE_SUCCESS) {
					ctx.crypto_state_handles[slot] = 0;
					if (ctx.state_key_slots[slot] <
					    CORE_FUZZ_TA_SLOTS) {
						ctx.crypto_object_handles[
							ctx.state_key_slots[slot]] = 0;
						ctx.state_key_slots[slot] = UINT8_MAX;
					}
				}
			}
			break;
		case CORE_FUZZ_TA_OBJ_ALLOC: {
			unsigned long type = TEE_TYPE_HMAC_SHA256;
			uint32_t handle = 0;

			if (selector == 1)
				type = TEE_TYPE_GENERIC_SECRET;
			else if (selector == 2)
				type = TEE_TYPE_AES;
			else if (selector == 3)
				type = TEE_TYPE_HKDF_IKM;
			else if (selector == 4)
				type = TEE_TYPE_RSA_KEYPAIR;
			else if (selector) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			if (ctx.crypto_object_handles[slot]) {
				step = TEE_ERROR_BAD_STATE;
				break;
			}
			step = _utee_cryp_obj_alloc(type, aux ? aux : 256,
						    &handle);
			if (step == TEE_SUCCESS)
				ctx.crypto_object_handles[slot] = handle;
			else if (handle)
				_utee_cryp_obj_close(handle);
			break;
		}
		case CORE_FUZZ_TA_OBJ_POPULATE: {
			struct utee_attribute attr = {
				.a = (uintptr_t)data,
				.b = data_len,
				.attribute_id = selector == 1 ? TEE_ATTR_HKDF_IKM :
					TEE_ATTR_SECRET_VALUE,
			};

			if (selector > 1) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			step = _utee_cryp_obj_populate(
				ctx.crypto_object_handles[slot], &attr, 1);
			break;
		}
		case CORE_FUZZ_TA_OBJ_CLOSE:
			step = _utee_cryp_obj_close(ctx.crypto_object_handles[slot]);
			if (step == TEE_SUCCESS)
				ctx.crypto_object_handles[slot] = 0;
			break;
		case CORE_FUZZ_TA_OBJ_GET_INFO: {
			struct utee_object_info info = { 0 };

			step = _utee_cryp_obj_get_info(
				ctx.crypto_object_handles[slot], &info);
			if (step == TEE_SUCCESS) {
				write_u16(record + 6, sizeof(info));
				TEE_MemMove(record + 8, &info, sizeof(info));
			}
			break;
		}
		case CORE_FUZZ_TA_OBJ_RESTRICT_USAGE:
			step = _utee_cryp_obj_restrict_usage(
				ctx.crypto_object_handles[slot], aux);
			break;
		case CORE_FUZZ_TA_OBJ_RESET:
			step = _utee_cryp_obj_reset(ctx.crypto_object_handles[slot]);
			break;
		case CORE_FUZZ_TA_OBJ_GET_ATTR: {
			uint8_t value[32] = { 0 };
			uint64_t value_len = aux;
			uint32_t attr_id = selector ? selector :
				TEE_ATTR_SECRET_VALUE;

			if (aux > sizeof(value)) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			step = _utee_cryp_obj_get_attr(
				ctx.crypto_object_handles[slot], attr_id,
				value, &value_len);
			if (value_len > UINT16_MAX)
				value_len = UINT16_MAX;
			write_u16(record + 6, value_len);
			if (step == TEE_SUCCESS && value_len <= sizeof(value))
				TEE_MemMove(record + 8, value, value_len);
			break;
		}
		case CORE_FUZZ_TA_OBJ_COPY:
			if (selector >= CORE_FUZZ_TA_SLOTS) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			step = _utee_cryp_obj_copy(
				ctx.crypto_object_handles[slot],
				ctx.crypto_object_handles[selector]);
			break;
		case CORE_FUZZ_TA_OBJ_GENERATE_KEY:
			step = _utee_cryp_obj_generate_key(
				ctx.crypto_object_handles[slot],
				aux ? aux : 256, NULL, 0);
			break;
		case CORE_FUZZ_TA_STATE_COPY:
			if (selector >= CORE_FUZZ_TA_SLOTS) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			step = _utee_cryp_state_copy(
				ctx.crypto_state_handles[slot],
				ctx.crypto_state_handles[selector]);
			break;
		case CORE_FUZZ_TA_CIPHER_INIT:
			step = _utee_cipher_init(ctx.crypto_state_handles[slot],
						 data, data_len);
			break;
		case CORE_FUZZ_TA_CIPHER_UPDATE:
		case CORE_FUZZ_TA_CIPHER_FINAL: {
			uint8_t value[CORE_FUZZ_TA_TEMP_OUTPUT_SIZE] = { 0 };
			uint64_t value_len = aux;

			if (aux > sizeof(value)) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			if (opcode == CORE_FUZZ_TA_CIPHER_UPDATE)
				step = _utee_cipher_update(
					ctx.crypto_state_handles[slot], data,
					data_len, value, &value_len);
			else
				step = _utee_cipher_final(
					ctx.crypto_state_handles[slot], data,
					data_len, value, &value_len);
			write_result_length(record, value_len);
			if (step == TEE_SUCCESS)
				copy_result_prefix(record, value, value_len);
			break;
		}
		case CORE_FUZZ_TA_DERIVE_KEY: {
			struct utee_attribute attrs[2] = {
				{ .attribute_id = TEE_ATTR_KDF_KEY_SIZE, .a = aux },
				{ .attribute_id = TEE_ATTR_HKDF_SALT,
				  .a = (uintptr_t)data, .b = data_len },
			};

			if (selector >= CORE_FUZZ_TA_SLOTS ||
			    aux > CORE_FUZZ_TA_TEMP_OUTPUT_SIZE) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			step = _utee_cryp_derive_key(
				ctx.crypto_state_handles[slot], attrs,
				data_len ? 2 : 1,
				ctx.crypto_object_handles[selector]);
			break;
		}
		case CORE_FUZZ_TA_RANDOM: {
			uint8_t value[CORE_FUZZ_TA_TEMP_OUTPUT_SIZE] = { 0 };

			if (aux > sizeof(value)) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			step = _utee_cryp_random_number_generate(value, aux);
			if (step == TEE_SUCCESS) {
				write_result_length(record, aux);
				copy_result_prefix(record, value, aux);
			}
			break;
		}
		case CORE_FUZZ_TA_AUTHENC_INIT: {
			size_t tag_len = selector ? selector : 16;

			if (tag_len > 16) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			step = _utee_authenc_init(ctx.crypto_state_handles[slot],
				data, data_len, tag_len, aux >> 8, aux & 0xff);
			break;
		}
		case CORE_FUZZ_TA_AUTHENC_UPDATE_AAD:
			step = _utee_authenc_update_aad(
				ctx.crypto_state_handles[slot], data, data_len);
			break;
		case CORE_FUZZ_TA_AUTHENC_UPDATE_PAYLOAD: {
			uint8_t value[CORE_FUZZ_TA_TEMP_OUTPUT_SIZE] = { 0 };
			uint64_t value_len = aux;

			if (aux > sizeof(value)) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			step = _utee_authenc_update_payload(
				ctx.crypto_state_handles[slot], data, data_len,
				value, &value_len);
			write_result_length(record, value_len);
			if (step == TEE_SUCCESS)
				copy_result_prefix(record, value, value_len);
			break;
		}
		case CORE_FUZZ_TA_AUTHENC_ENC_FINAL: {
			uint8_t value[CORE_FUZZ_TA_TEMP_OUTPUT_SIZE] = { 0 };
			uint8_t tag[16] = { 0 };
			uint64_t value_len = aux;
			uint64_t tag_len = selector ? selector : sizeof(tag);

			if (aux > sizeof(value) || tag_len > sizeof(tag)) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			step = _utee_authenc_enc_final(
				ctx.crypto_state_handles[slot], data, data_len,
				value, &value_len, tag, &tag_len);
			write_result_length(record, value_len);
			if (step == TEE_SUCCESS) {
				TEE_MemMove(record + 8, value,
					    value_len > 16 ? 16 : value_len);
				TEE_MemMove(record + 24, tag,
					    tag_len > 16 ? 16 : tag_len);
			}
			break;
		}
		case CORE_FUZZ_TA_AUTHENC_DEC_FINAL: {
			uint8_t value[CORE_FUZZ_TA_TEMP_OUTPUT_SIZE] = { 0 };
			uint64_t value_len = aux;
			size_t tag_len = selector ? selector : 16;

			if (aux > sizeof(value) || tag_len > 16 ||
			    data_len < tag_len) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			step = _utee_authenc_dec_final(
				ctx.crypto_state_handles[slot], data + tag_len,
				data_len - tag_len, value, &value_len,
				data, tag_len);
			write_result_length(record, value_len);
			if (step == TEE_SUCCESS)
				copy_result_prefix(record, value, value_len);
			break;
		}
		case CORE_FUZZ_TA_ASYMM_OPERATE: {
			uint8_t value[CORE_FUZZ_TA_TEMP_OUTPUT_SIZE] = { 0 };
			const void *src_data = data;
			size_t src_len = data_len;
			uint64_t value_len = aux;

			if (selector > 1 || aux > sizeof(value)) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			if (selector == 1) {
				if (!ctx.asymm_result_len) {
					step = TEE_ERROR_BAD_STATE;
					break;
				}
				src_data = ctx.asymm_result;
				src_len = ctx.asymm_result_len;
			}
			step = _utee_asymm_operate(ctx.crypto_state_handles[slot],
				NULL, 0, src_data, src_len, value, &value_len);
			write_result_length(record, value_len);
			if (step == TEE_SUCCESS) {
				copy_result_prefix(record, value, value_len);
				ctx.asymm_result_len =
					value_len > sizeof(ctx.asymm_result) ?
					sizeof(ctx.asymm_result) : value_len;
				TEE_MemMove(ctx.asymm_result, value,
					    ctx.asymm_result_len);
			}
			break;
		}
		case CORE_FUZZ_TA_ASYMM_VERIFY: {
			const uint8_t *signature = NULL;
			size_t signature_len = 0;
			size_t digest_len = data_len;

			if (selector == 1) {
				signature = ctx.asymm_result;
				signature_len = ctx.asymm_result_len;
			} else if (selector == 0 && aux <= data_len) {
				digest_len = aux;
				signature = data + aux;
				signature_len = data_len - aux;
			} else {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			step = _utee_asymm_verify(ctx.crypto_state_handles[slot],
				NULL, 0, data, digest_len, signature,
				signature_len);
			break;
		}
		default:
			/* Unknown opcodes are reported as per-step errors. */
			step = TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		write_u32(record, step);
		if (target_coverage && i == target_index) {
			result = end_coverage(coverage_session, params);
			if (result != TEE_SUCCESS)
				goto out;
			coverage_started = false;
		}
		offset += CORE_FUZZ_TA_OP_HEADER_SIZE + data_len;
	}

	TEE_MemMove(params[1].memref.buffer, output, output_size);

out:
	for (i = 0; i < CORE_FUZZ_TA_SLOTS; i++) {
		if (ctx.crypto_state_handles[i]) {
			_utee_cryp_state_free(ctx.crypto_state_handles[i]);
			if (ctx.state_key_slots[i] < CORE_FUZZ_TA_SLOTS)
				ctx.crypto_object_handles[
					ctx.state_key_slots[i]] = 0;
		}
	}
	for (i = 0; i < CORE_FUZZ_TA_SLOTS; i++)
		if (ctx.crypto_object_handles[i])
			_utee_cryp_obj_close(ctx.crypto_object_handles[i]);
	if (coverage_started) {
		TEE_Result coverage_result = end_coverage(coverage_session,
								params);

		if (result == TEE_SUCCESS)
			result = coverage_result;
	}
	if (coverage_session != TEE_HANDLE_NULL)
		TEE_CloseTASession(coverage_session);
	TEE_Free(output);
	TEE_Free(input);
	return result;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
	TEE_Param params[4], void **session_context)
{
	(void)params;
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;
	*session_context = NULL;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session_context)
{
	(void)session_context;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_context,
	uint32_t command_id, uint32_t param_types, TEE_Param params[4])
{
	(void)session_context;
	if (command_id != CORE_FUZZ_TA_CMD_RUN)
		return TEE_ERROR_NOT_SUPPORTED;
	return run(param_types, params);
}
