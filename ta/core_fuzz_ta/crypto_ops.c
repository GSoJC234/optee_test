// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Jaehun Lee
 */

#include <core_fuzz_ta.h>
#include <crypto_ops.h>
#include <tee_api_defines_extensions.h>
#include <tee_internal_api.h>
#include <utee_syscalls.h>
#include <stddef.h>
#include <stdint.h>

static uint16_t read_u16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
		((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Result records double as the invocation's full-output cache. */
static const uint8_t *prior_result(const uint8_t *records,
				   size_t prior_count, size_t index,
				   uint8_t expected_op,
				   uint8_t alternate_op)
{
	const uint8_t *record = NULL;

	if (index >= prior_count)
		return NULL;
	record = records + index * CORE_FUZZ_TA_RESULT_SIZE;
	if (read_u32(record) != TEE_SUCCESS ||
	    (record[4] != expected_op && record[4] != alternate_op) ||
	    read_u16(record + 6) > CORE_FUZZ_TA_RESULT_DATA_SIZE)
		return NULL;
	return record;
}

static void write_u16(uint8_t *p, uint16_t value)
{
	p[0] = (uint8_t)value;
	p[1] = (uint8_t)(value >> 8);
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

TEE_Result crypto_execute(struct fuzz_context *ctx,
			  const struct fuzz_op *op, uint8_t *record,
			  const uint8_t *prior_records, size_t prior_count)
{
	const uint8_t opcode = op->opcode;
	const uint8_t slot = op->slot;
	const uint8_t selector = op->selector;
	const uint16_t data_len = op->data_len;
	const uint16_t aux = op->aux;
	const uint8_t *data = op->data;
	TEE_Result step = TEE_SUCCESS;

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
		case 18:
		case 19:
			algo = TEE_ALG_ECDSA_SHA256;
			mode = selector == 18 ? TEE_MODE_SIGN :
				TEE_MODE_VERIFY;
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
			key = ctx->crypto_object_handles[aux];
		}
		if (ctx->crypto_state_handles[slot]) {
			step = TEE_ERROR_BAD_STATE;
		} else {
			uint32_t handle = 0;

			step = _utee_cryp_state_alloc(algo, mode, key, 0,
						     &handle);
			if (step == TEE_SUCCESS) {
				ctx->crypto_state_handles[slot] = handle;
				if (selector >= 2)
					ctx->state_key_slots[slot] = (uint8_t)aux;
			} else if (handle) {
				_utee_cryp_state_free(handle);
			}
		}
		break;
	}
	case CORE_FUZZ_TA_INIT:
		step = _utee_hash_init(ctx->crypto_state_handles[slot],
				       NULL, 0);
		break;
	case CORE_FUZZ_TA_UPDATE:
		step = _utee_hash_update(ctx->crypto_state_handles[slot],
					 data, data_len);
		break;
	case CORE_FUZZ_TA_FINAL: {
		uint8_t digest[64] = { 0 };
		uint64_t digest_len = aux;

		if (aux > sizeof(digest)) {
			step = TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		step = _utee_hash_final(ctx->crypto_state_handles[slot],
					data, data_len, digest,
					&digest_len);
		if (digest_len > UINT16_MAX)
			digest_len = UINT16_MAX;
		write_result_length(record, digest_len);
		if (step == TEE_SUCCESS && digest_len <= sizeof(digest))
			copy_result_prefix(record, digest, digest_len);
		break;
	}
	case CORE_FUZZ_TA_FREE:
		if (!ctx->crypto_state_handles[slot]) {
			step = TEE_ERROR_BAD_STATE;
		} else {
			step = _utee_cryp_state_free(
				ctx->crypto_state_handles[slot]);
			if (step == TEE_SUCCESS) {
				ctx->crypto_state_handles[slot] = 0;
				if (ctx->state_key_slots[slot] <
				    CORE_FUZZ_TA_SLOTS) {
					ctx->crypto_object_handles[
						ctx->state_key_slots[slot]] = 0;
					ctx->state_key_slots[slot] = UINT8_MAX;
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
		else if (selector == 5)
			type = TEE_TYPE_RSA_PUBLIC_KEY;
		else if (selector == 6)
			type = TEE_TYPE_ECDSA_KEYPAIR;
		else if (selector == 7)
			type = TEE_TYPE_ECDSA_PUBLIC_KEY;
		else if (selector) {
			step = TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		if (ctx->crypto_object_handles[slot]) {
			step = TEE_ERROR_BAD_STATE;
			break;
		}
		step = _utee_cryp_obj_alloc(type, aux ? aux : 256,
					    &handle);
		if (step == TEE_SUCCESS)
			ctx->crypto_object_handles[slot] = handle;
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
			ctx->crypto_object_handles[slot], &attr, 1);
		break;
	}
	case CORE_FUZZ_TA_OBJ_CLOSE:
		step = _utee_cryp_obj_close(ctx->crypto_object_handles[slot]);
		if (step == TEE_SUCCESS)
			ctx->crypto_object_handles[slot] = 0;
		break;
	case CORE_FUZZ_TA_OBJ_GET_INFO: {
		struct utee_object_info info = { 0 };

		step = _utee_cryp_obj_get_info(
			ctx->crypto_object_handles[slot], &info);
		if (step == TEE_SUCCESS) {
			write_u16(record + 6, sizeof(info));
			TEE_MemMove(record + 8, &info, sizeof(info));
		}
		break;
	}
	case CORE_FUZZ_TA_OBJ_RESTRICT_USAGE:
		step = _utee_cryp_obj_restrict_usage(
			ctx->crypto_object_handles[slot], aux);
		break;
	case CORE_FUZZ_TA_OBJ_RESET:
		step = _utee_cryp_obj_reset(ctx->crypto_object_handles[slot]);
		break;
	case CORE_FUZZ_TA_OBJ_GET_ATTR: {
		uint8_t value[CORE_FUZZ_TA_RESULT_DATA_SIZE] = { 0 };
		uint64_t value_len = aux;
		uint32_t attr_id = selector ? selector :
			TEE_ATTR_SECRET_VALUE;

		if (aux > sizeof(value)) {
			step = TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		step = _utee_cryp_obj_get_attr(
			ctx->crypto_object_handles[slot], attr_id,
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
			ctx->crypto_object_handles[slot],
			ctx->crypto_object_handles[selector]);
		break;
	case CORE_FUZZ_TA_OBJ_GENERATE_KEY: {
		struct utee_attribute curve = {
			.attribute_id = TEE_ATTR_ECC_CURVE,
			.a = TEE_ECC_CURVE_NIST_P256,
		};

		step = _utee_cryp_obj_generate_key(
			ctx->crypto_object_handles[slot], aux ? aux : 256,
			selector == 1 ? &curve : NULL, selector == 1 ? 1 : 0);
		break;
	}
	case CORE_FUZZ_TA_STATE_COPY:
		if (selector >= CORE_FUZZ_TA_SLOTS) {
			step = TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		step = _utee_cryp_state_copy(
			ctx->crypto_state_handles[slot],
			ctx->crypto_state_handles[selector]);
		break;
	case CORE_FUZZ_TA_CIPHER_INIT:
		step = _utee_cipher_init(ctx->crypto_state_handles[slot],
					 data, data_len);
		break;
	case CORE_FUZZ_TA_CIPHER_UPDATE:
	case CORE_FUZZ_TA_CIPHER_FINAL: {
		uint8_t value[CORE_FUZZ_TA_TEMP_OUTPUT_SIZE] = { 0 };
		uint64_t value_len = aux;
		const uint8_t *src_data = data;
		size_t src_len = data_len;

		if (aux > sizeof(value)) {
			step = TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		if (selector == 0x80) {
			const uint8_t *src = NULL;

			if (data_len != 1) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			src = prior_result(prior_records, prior_count, data[0],
					   CORE_FUZZ_TA_CIPHER_UPDATE,
					   CORE_FUZZ_TA_CIPHER_FINAL);
			if (!src) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			src_data = src + 8;
			src_len = read_u16(src + 6);
		}
		if (opcode == CORE_FUZZ_TA_CIPHER_UPDATE)
			step = _utee_cipher_update(
				ctx->crypto_state_handles[slot], src_data,
				src_len, value, &value_len);
		else
			step = _utee_cipher_final(
				ctx->crypto_state_handles[slot], src_data,
				src_len, value, &value_len);
		write_result_length(record, value_len);
		if (step == TEE_SUCCESS && value_len <= sizeof(value))
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
			ctx->crypto_state_handles[slot], attrs,
			data_len ? 2 : 1,
			ctx->crypto_object_handles[selector]);
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
		step = _utee_authenc_init(ctx->crypto_state_handles[slot],
			data, data_len, tag_len, aux >> 8, aux & 0xff);
		break;
	}
	case CORE_FUZZ_TA_AUTHENC_UPDATE_AAD:
		step = _utee_authenc_update_aad(
			ctx->crypto_state_handles[slot], data, data_len);
		break;
	case CORE_FUZZ_TA_AUTHENC_UPDATE_PAYLOAD: {
		uint8_t value[CORE_FUZZ_TA_TEMP_OUTPUT_SIZE] = { 0 };
		uint64_t value_len = aux;

		if (aux > sizeof(value)) {
			step = TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		step = _utee_authenc_update_payload(
			ctx->crypto_state_handles[slot], data, data_len,
			value, &value_len);
		write_result_length(record, value_len);
		if (step == TEE_SUCCESS && value_len <= sizeof(value))
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
			ctx->crypto_state_handles[slot], data, data_len,
			value, &value_len, tag, &tag_len);
		write_result_length(record, value_len);
		if (step == TEE_SUCCESS && value_len <= sizeof(value) &&
		    tag_len <= sizeof(tag)) {
			copy_result_prefix(record, value, value_len);
			TEE_MemMove(record + 8 + CORE_FUZZ_TA_RESULT_DATA_SIZE,
				    tag, tag_len);
			ctx->tag_lens[prior_count] = tag_len;
		}
		break;
	}
	case CORE_FUZZ_TA_AUTHENC_DEC_FINAL: {
		uint8_t value[CORE_FUZZ_TA_TEMP_OUTPUT_SIZE] = { 0 };
		uint64_t value_len = aux;
		size_t tag_len = selector & 0x7f;
		const uint8_t *tag = data;
		const uint8_t *src_data = NULL;
		size_t src_len = 0;

		if (!tag_len)
			tag_len = 16;

		if (aux > sizeof(value) || tag_len > 16) {
			step = TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		if (selector & 0x80) {
			const uint8_t *src = NULL;

			if (data_len != 1) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			src = prior_result(prior_records, prior_count, data[0],
					   CORE_FUZZ_TA_AUTHENC_ENC_FINAL,
					   CORE_FUZZ_TA_AUTHENC_ENC_FINAL);
			if (!src || ctx->tag_lens[data[0]] != tag_len) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			tag = src + 8 + CORE_FUZZ_TA_RESULT_DATA_SIZE;
			src_data = src + 8;
			src_len = read_u16(src + 6);
		} else {
			if (data_len < tag_len) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			src_data = data + tag_len;
			src_len = data_len - tag_len;
		}
		step = _utee_authenc_dec_final(
			ctx->crypto_state_handles[slot], src_data,
			src_len, value, &value_len, tag, tag_len);
		write_result_length(record, value_len);
		if (step == TEE_SUCCESS && value_len <= sizeof(value))
			copy_result_prefix(record, value, value_len);
		break;
	}
	case CORE_FUZZ_TA_ASYMM_OPERATE: {
		uint8_t value[CORE_FUZZ_TA_TEMP_OUTPUT_SIZE] = { 0 };
		const void *src_data = data;
		size_t src_len = data_len;
		uint64_t value_len = aux;

		if (selector > 2 || aux > sizeof(value)) {
			step = TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		if (selector == 1) {
			if (!ctx->asymm_result_len) {
				step = TEE_ERROR_BAD_STATE;
				break;
			}
			src_data = ctx->asymm_result;
			src_len = ctx->asymm_result_len;
		} else if (selector == 2) {
			const uint8_t *src = NULL;

			if (data_len != 1) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			src = prior_result(prior_records, prior_count, data[0],
					   CORE_FUZZ_TA_ASYMM_OPERATE,
					   CORE_FUZZ_TA_ASYMM_OPERATE);
			if (!src) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			src_data = src + 8;
			src_len = read_u16(src + 6);
		}
		step = _utee_asymm_operate(ctx->crypto_state_handles[slot],
			NULL, 0, src_data, src_len, value, &value_len);
		write_result_length(record, value_len);
		if (step == TEE_SUCCESS && value_len <= sizeof(value)) {
			copy_result_prefix(record, value, value_len);
			ctx->asymm_result_len = value_len;
			TEE_MemMove(ctx->asymm_result, value,
				    ctx->asymm_result_len);
		}
		break;
	}
	case CORE_FUZZ_TA_ASYMM_VERIFY: {
		const uint8_t *signature = NULL;
		size_t signature_len = 0;
		size_t digest_len = data_len;

		if (selector == 1) {
			signature = ctx->asymm_result;
			signature_len = ctx->asymm_result_len;
		} else if (selector == 2) {
			const uint8_t *src = prior_result(prior_records,
				prior_count, aux,
				CORE_FUZZ_TA_ASYMM_OPERATE,
				CORE_FUZZ_TA_ASYMM_OPERATE);

			if (!src) {
				step = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			signature = src + 8;
			signature_len = read_u16(src + 6);
		} else if (selector == 0 && aux <= data_len) {
			digest_len = aux;
			signature = data + aux;
			signature_len = data_len - aux;
		} else {
			step = TEE_ERROR_BAD_PARAMETERS;
			break;
		}
		step = _utee_asymm_verify(ctx->crypto_state_handles[slot],
			NULL, 0, data, digest_len, signature,
			signature_len);
		break;
	}
	default:
		/* Unknown opcodes are reported as per-step errors. */
		step = TEE_ERROR_BAD_PARAMETERS;
		break;
	}
	return step;
}

void crypto_cleanup(struct fuzz_context *ctx)
{
	uint8_t i = 0;

	for (i = 0; i < CORE_FUZZ_TA_SLOTS; i++) {
		if (ctx->crypto_state_handles[i]) {
			_utee_cryp_state_free(ctx->crypto_state_handles[i]);
			if (ctx->state_key_slots[i] < CORE_FUZZ_TA_SLOTS)
				ctx->crypto_object_handles[
					ctx->state_key_slots[i]] = 0;
		}
	}
	for (i = 0; i < CORE_FUZZ_TA_SLOTS; i++)
		if (ctx->crypto_object_handles[i])
			_utee_cryp_obj_close(ctx->crypto_object_handles[i]);
}
