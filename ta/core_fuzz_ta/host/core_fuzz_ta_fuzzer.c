// SPDX-License-Identifier: BSD-2-Clause
#define _POSIX_C_SOURCE 200809L
#include <core_fuzz_ta.h>
#include <pta_core_fuzz_cov.h>
#include <tee_client_api.h>

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define COVERAGE_SIZE PTA_CORE_FUZZ_COV_MAP_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX_CORPUS_ENTRIES 4096U
#define MAX_CRITERIA 8U
#define MAX_MUTATION_ATTEMPTS 16U
#define MAX_LEARNED_ENTRIES 1024U
#define MAX_PREFIX_PROBES 16U
#define MAX_ASSEMBLY_SAMPLES 32U
#define PATH_CAP 4096U
#define EFFECT_COVERAGE 1U
#define EFFECT_RECORD 2U

/* The guest fuzzer is single threaded. Include replays and learner probes. */
static uint64_t ta_invocations;
/* Count only per-step records returned by successful TA invocations. */
static uint64_t opcode_calls[CORE_FUZZ_TA_ASYMM_VERIFY + 1];
static uint64_t opcode_success[CORE_FUZZ_TA_ASYMM_VERIFY + 1];

struct input {
	uint8_t *bytes;
	size_t size;
};

struct corpus {
	struct input entries[MAX_CORPUS_ENTRIES];
	size_t count;
};

struct rng {
	uint64_t state;
};

struct execution {
	TEEC_Result result;
	uint32_t origin;
	bool session_opened;
	bool coverage_valid;
	/* -1 captures the entire invocation; otherwise only one command. */
	int target_index;
	uint8_t target_opcode;
	uint8_t coverage[COVERAGE_SIZE];
	uint8_t response[CORE_FUZZ_TA_MAX_OUTPUT];
	size_t response_size;
};

/* Criteria operate on two executions, so nondeterministic features can be
 * rejected before they enter the corpus. Add later criteria to this registry.
 */
struct feedback_criterion {
	const char *name;
	void *state;
	size_t (*new_features)(void *state, const struct execution *a,
				const struct execution *b);
	void (*commit)(void *state, const struct execution *a,
		       const struct execution *b);
};

struct feedback {
	struct feedback_criterion criteria[MAX_CRITERIA];
	size_t count;
};

struct coverage_state {
	uint8_t seen[COVERAGE_SIZE];
	size_t total;
};

struct target_coverage_state {
	uint8_t seen[CORE_FUZZ_TA_ASYMM_VERIFY + 1][COVERAGE_SIZE];
	size_t total;
};

struct learned_entry {
	size_t corpus_index;
	uint8_t target_index;
	uint8_t target_opcode;
	/* Only verified, same-slot predecessors are used for assembly. */
	bool assemblable;
};

struct learned_pool {
	struct learned_entry entries[MAX_LEARNED_ENTRIES];
	size_t count;
	size_t relations;
	size_t assemblable;
};

struct hopper_module {
	bool enabled;
	struct target_coverage_state target_coverage;
	struct learned_pool learned;
	size_t assembly_attempts;
	size_t assemblies;
	size_t assembly_new_edges;
	size_t assembly_target_new_edges;
	size_t assembly_crashes;
	size_t assembly_samples;
	size_t assembly_target_records;
	size_t assembly_target_success;
};

struct generated_case {
	size_t parent;
	size_t size;
	size_t template_index;
	int assembled_target;
	uint8_t assembled_opcode;
	bool assembled;
};

struct op_view {
	const uint8_t *header;
	const uint8_t *data;
	uint16_t data_size;
};

struct parsed_input {
	struct op_view ops[CORE_FUZZ_TA_MAX_OPS];
	uint8_t count;
};

static uint16_t read_u16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void write_u16(uint8_t *p, uint16_t value)
{
	p[0] = (uint8_t)value;
	p[1] = (uint8_t)(value >> 8);
}

static uint64_t next_random(struct rng *rng)
{
	uint64_t value = rng->state;

	value ^= value >> 12;
	value ^= value << 25;
	value ^= value >> 27;
	rng->state = value;
	return value * UINT64_C(2685821657736338717);
}

static size_t random_below(struct rng *rng, size_t limit)
{
	return limit ? (size_t)(next_random(rng) % limit) : 0;
}

static bool parse_input(const uint8_t *bytes, size_t size,
			struct parsed_input *parsed)
{
	size_t offset = CORE_FUZZ_TA_INPUT_HEADER_SIZE;
	size_t i = 0;

	if (size < CORE_FUZZ_TA_INPUT_HEADER_SIZE ||
	    bytes[5] > CORE_FUZZ_TA_MAX_OPS)
		return false;
	parsed->count = bytes[5];
	for (i = 0; i < parsed->count; i++) {
		struct op_view *op = &parsed->ops[i];

		if (size - offset < CORE_FUZZ_TA_OP_HEADER_SIZE)
			return false;
		op->header = bytes + offset;
		op->data_size = read_u16(bytes + offset + 3);
		if (op->header[1] >= CORE_FUZZ_TA_SLOTS ||
		    op->data_size > size - offset -
				    CORE_FUZZ_TA_OP_HEADER_SIZE ||
		    (op->header[0] == CORE_FUZZ_TA_FINAL &&
		     read_u16(op->header + 5) > 64) ||
		    (op->header[0] == CORE_FUZZ_TA_OBJ_GET_ATTR &&
		     read_u16(op->header + 5) > 32))
			return false;
		op->data = bytes + offset + CORE_FUZZ_TA_OP_HEADER_SIZE;
		offset += CORE_FUZZ_TA_OP_HEADER_SIZE + op->data_size;
	}
	return true;
}

static bool append_op(uint8_t *out, size_t *size,
		      const uint8_t header[CORE_FUZZ_TA_OP_HEADER_SIZE],
		      const uint8_t *data, size_t data_size)
{
	if (data_size > UINT16_MAX ||
	    *size + CORE_FUZZ_TA_OP_HEADER_SIZE + data_size >
		CORE_FUZZ_TA_MAX_INPUT)
		return false;
	memcpy(out + *size, header, CORE_FUZZ_TA_OP_HEADER_SIZE);
	write_u16(out + *size + 3, (uint16_t)data_size);
	*size += CORE_FUZZ_TA_OP_HEADER_SIZE;
	if (data_size)
		memcpy(out + *size, data, data_size);
	*size += data_size;
	return true;
}

static uint8_t random_opcode(struct rng *rng)
{
	return CORE_FUZZ_TA_ALLOC +
		random_below(rng, CORE_FUZZ_TA_ASYMM_VERIFY);
}

static void initialize_op_fields(uint8_t header[CORE_FUZZ_TA_OP_HEADER_SIZE],
				 struct rng *rng)
{
	static const uint16_t attr_caps[] = { 0, 1, 16, 31, 32 };

	header[2] = 0;
	write_u16(header + 5, 0);
	switch (header[0]) {
	case CORE_FUZZ_TA_ALLOC:
		header[2] = random_below(rng, 18);
		if (header[2] >= 2)
			write_u16(header + 5,
				  random_below(rng, CORE_FUZZ_TA_SLOTS));
		break;
	case CORE_FUZZ_TA_FINAL:
		write_u16(header + 5, random_below(rng, 4) ? 32 : 64);
		break;
	case CORE_FUZZ_TA_OBJ_ALLOC:
		header[2] = random_below(rng, 5);
		write_u16(header + 5, header[2] == 4 ?
			  (random_below(rng, 2) ? 1024 : 2048) :
			  (random_below(rng, 4) ? 256 : 128));
		break;
	case CORE_FUZZ_TA_OBJ_POPULATE:
		header[2] = random_below(rng, 2);
		break;
	case CORE_FUZZ_TA_OBJ_RESTRICT_USAGE:
		write_u16(header + 5, random_below(rng, 2) ? 8 : 0);
		break;
	case CORE_FUZZ_TA_OBJ_GET_ATTR:
		write_u16(header + 5,
			  attr_caps[random_below(rng, sizeof(attr_caps) /
						 sizeof(attr_caps[0]))]);
		break;
	case CORE_FUZZ_TA_OBJ_COPY:
	case CORE_FUZZ_TA_STATE_COPY:
		header[2] = random_below(rng, CORE_FUZZ_TA_SLOTS);
		break;
	case CORE_FUZZ_TA_OBJ_GENERATE_KEY:
		write_u16(header + 5, random_below(rng, 4) ? 256 :
			  (random_below(rng, 2) ? 1024 : 2048));
		break;
	case CORE_FUZZ_TA_CIPHER_UPDATE:
	case CORE_FUZZ_TA_CIPHER_FINAL:
	case CORE_FUZZ_TA_AUTHENC_UPDATE_PAYLOAD:
	case CORE_FUZZ_TA_ASYMM_OPERATE:
		write_u16(header + 5, random_below(rng, 4) ? 256 : 32);
		break;
	case CORE_FUZZ_TA_RANDOM:
		write_u16(header + 5, random_below(rng, 4) ? 32 : 256);
		break;
	case CORE_FUZZ_TA_AUTHENC_INIT:
		/* The high and low bytes of aux are AAD and payload lengths. */
		header[2] = 16;
		write_u16(header + 5, 0);
		break;
	case CORE_FUZZ_TA_AUTHENC_ENC_FINAL:
	case CORE_FUZZ_TA_AUTHENC_DEC_FINAL:
		header[2] = 16;
		write_u16(header + 5, 256);
		break;
	case CORE_FUZZ_TA_DERIVE_KEY:
		header[2] = random_below(rng, CORE_FUZZ_TA_SLOTS);
		write_u16(header + 5, 32);
		break;
	case CORE_FUZZ_TA_ASYMM_VERIFY:
		header[2] = 1;
		break;
	default:
		break;
	}
}

static bool append_new_op(uint8_t *out, size_t *size, struct rng *rng,
			  int forced_slot)
{
	uint8_t header[CORE_FUZZ_TA_OP_HEADER_SIZE] = { 0 };
	uint8_t payload[64] = { 0 };
	size_t data_size = 0;

	header[0] = random_opcode(rng);
	header[1] = forced_slot < 0 ?
		(uint8_t)random_below(rng, CORE_FUZZ_TA_SLOTS) :
		(uint8_t)forced_slot;
	initialize_op_fields(header, rng);
	if (header[0] == CORE_FUZZ_TA_UPDATE ||
	    header[0] == CORE_FUZZ_TA_FINAL) {
		data_size = random_below(rng, 5);
	} else if (header[0] == CORE_FUZZ_TA_OBJ_POPULATE) {
		data_size = random_below(rng, 4) ? 32 :
			1 + random_below(rng, sizeof(payload));
	} else if (header[0] == CORE_FUZZ_TA_CIPHER_INIT) {
		data_size = 16;
	} else if (header[0] == CORE_FUZZ_TA_AUTHENC_INIT) {
		data_size = 12;
	} else if (header[0] == CORE_FUZZ_TA_AUTHENC_DEC_FINAL) {
		data_size = 16 + random_below(rng, 33);
	} else if (header[0] == CORE_FUZZ_TA_CIPHER_UPDATE ||
		   header[0] == CORE_FUZZ_TA_CIPHER_FINAL ||
		   header[0] == CORE_FUZZ_TA_DERIVE_KEY ||
		   header[0] == CORE_FUZZ_TA_AUTHENC_UPDATE_AAD ||
		   header[0] == CORE_FUZZ_TA_AUTHENC_UPDATE_PAYLOAD ||
		   header[0] == CORE_FUZZ_TA_AUTHENC_ENC_FINAL ||
		   header[0] == CORE_FUZZ_TA_ASYMM_OPERATE ||
		   header[0] == CORE_FUZZ_TA_ASYMM_VERIFY) {
		data_size = random_below(rng, 4) ? 32 : 16;
	}
	for (size_t i = 0; i < data_size; i++)
		payload[i] = (uint8_t)next_random(rng);
	return append_op(out, size, header, payload, data_size);
}

static bool mutate_structured(const uint8_t *input, size_t input_size,
			      uint8_t *out, size_t *out_size,
			      struct rng *rng, bool hopper_enabled)
{
	static const uint16_t payload_boundaries[] = {
		0, 1, 2, 31, 32, 63, 64, 65, 127, 128, 129, 256
	};
	static const uint16_t final_boundaries[] = { 0, 1, 31, 32, 33, 64 };
	static const uint16_t object_size_boundaries[] = {
		0, 8, 128, 192, 256, 512, 1024, 2048
	};
	static const uint16_t output_boundaries[] = {
		0, 1, 16, 31, 32, 64, 128, 256, 257
	};
	static const uint8_t tag_boundaries[] = { 0, 4, 8, 12, 16, 17 };
	static const uint16_t attr_boundaries[] = { 0, 1, 31, 32 };
	static const uint16_t usage_boundaries[] = { 0, 8, 0xffff };
	struct parsed_input parsed = { 0 };
	uint8_t scratch[CORE_FUZZ_TA_MAX_INPUT];
	size_t target = 0;
	size_t action = 0;
	size_t count = 0;
	size_t size = CORE_FUZZ_TA_INPUT_HEADER_SIZE;
	size_t i = 0;

	if (!parse_input(input, input_size, &parsed))
		return false;
	memcpy(out, input, CORE_FUZZ_TA_INPUT_HEADER_SIZE);
	count = parsed.count;
	target = random_below(rng, count ? count : 1);
	action = random_below(rng, hopper_enabled ? 10 : 9);
	if (!count)
		action = 5;
	if (action == 5 && count == CORE_FUZZ_TA_MAX_OPS)
		return false;
	if (action == 7 && count == CORE_FUZZ_TA_MAX_OPS)
		return false;
	if (action == 8 && count < 2)
		return false;
	if (action == 9 && count == CORE_FUZZ_TA_MAX_OPS)
		return false;
	if (action == 8)
		target = random_below(rng, count - 1);

	for (i = 0; i < count; i++) {
		const struct op_view *op = NULL;
		uint8_t header[CORE_FUZZ_TA_OP_HEADER_SIZE];
		const uint8_t *data = NULL;
		size_t data_size = 0;
		size_t source = i;

		if (action == 5 && i == target &&
		    !append_new_op(out, &size, rng, -1))
			return false;
		if (action == 9 && i == target &&
		    !append_new_op(out, &size, rng,
				   parsed.ops[target].header[1]))
			return false;
		if (action == 6 && i == target)
			continue;
		if (action == 8 && i == target)
			source = i + 1;
		else if (action == 8 && i == target + 1)
			source = i - 1;
		op = &parsed.ops[source];
		memcpy(header, op->header, sizeof(header));
		data = op->data;
		data_size = op->data_size;
		if (i == target) {
			switch (action) {
			case 0:
				header[0] = random_opcode(rng);
				initialize_op_fields(header, rng);
				if (!data_size) {
					switch (header[0]) {
					case CORE_FUZZ_TA_OBJ_POPULATE:
					case CORE_FUZZ_TA_ASYMM_OPERATE:
					case CORE_FUZZ_TA_ASYMM_VERIFY:
						data_size = 32;
						break;
					case CORE_FUZZ_TA_CIPHER_INIT:
					case CORE_FUZZ_TA_DERIVE_KEY:
					case CORE_FUZZ_TA_AUTHENC_DEC_FINAL:
						data_size = 16;
						break;
					case CORE_FUZZ_TA_AUTHENC_INIT:
						data_size = 12;
						break;
					case CORE_FUZZ_TA_CIPHER_UPDATE:
					case CORE_FUZZ_TA_CIPHER_FINAL:
					case CORE_FUZZ_TA_AUTHENC_UPDATE_AAD:
					case CORE_FUZZ_TA_AUTHENC_UPDATE_PAYLOAD:
					case CORE_FUZZ_TA_AUTHENC_ENC_FINAL:
						data_size = 1;
						break;
					default:
						break;
					}
					for (size_t j = 0; j < data_size; j++)
						scratch[j] = (uint8_t)next_random(rng);
					if (data_size)
						data = scratch;
				}
				break;
			case 1:
				if (header[0] == CORE_FUZZ_TA_ALLOC &&
				    header[2] >= 2 && random_below(rng, 2))
					write_u16(header + 5,
						  random_below(rng,
							       CORE_FUZZ_TA_SLOTS));
				else if ((header[0] == CORE_FUZZ_TA_OBJ_COPY ||
					  header[0] == CORE_FUZZ_TA_STATE_COPY ||
					  header[0] == CORE_FUZZ_TA_DERIVE_KEY) &&
					 random_below(rng, 2))
					header[2] = random_below(rng,
							 CORE_FUZZ_TA_SLOTS);
				else
					header[1] = random_below(rng,
							CORE_FUZZ_TA_SLOTS);
				break;
			case 2:
				if (header[0] == CORE_FUZZ_TA_FINAL)
					write_u16(header + 5,
						final_boundaries[random_below(rng,
							 sizeof(final_boundaries) /
							 sizeof(final_boundaries[0]))]);
				else if (header[0] == CORE_FUZZ_TA_OBJ_GET_ATTR) {
					if (random_below(rng, 3))
						write_u16(header + 5,
							attr_boundaries[random_below(rng,
								sizeof(attr_boundaries) /
								sizeof(attr_boundaries[0]))]);
					else
						header[2] = random_below(rng, 4);
				} else if (header[0] == CORE_FUZZ_TA_OBJ_ALLOC &&
					 random_below(rng, 3) == 0)
					header[2] = random_below(rng, 5);
				else if (header[0] == CORE_FUZZ_TA_OBJ_ALLOC ||
					 header[0] == CORE_FUZZ_TA_OBJ_GENERATE_KEY)
					write_u16(header + 5,
						object_size_boundaries[random_below(rng,
							sizeof(object_size_boundaries) /
							sizeof(object_size_boundaries[0]))]);
				else if (header[0] == CORE_FUZZ_TA_OBJ_POPULATE)
					header[2] = random_below(rng, 2);
				else if (header[0] == CORE_FUZZ_TA_OBJ_RESTRICT_USAGE)
					write_u16(header + 5,
						usage_boundaries[random_below(rng,
							sizeof(usage_boundaries) /
							sizeof(usage_boundaries[0]))]);
				else if (header[0] == CORE_FUZZ_TA_ALLOC) {
					header[2] = random_below(rng, 18);
					if (header[2] >= 2)
						write_u16(header + 5,
						  random_below(rng,
							       CORE_FUZZ_TA_SLOTS));
				} else if (header[0] == CORE_FUZZ_TA_STATE_COPY)
					header[2] = random_below(rng,
							 CORE_FUZZ_TA_SLOTS);
				else if (header[0] == CORE_FUZZ_TA_DERIVE_KEY) {
					if (random_below(rng, 2))
						header[2] = random_below(rng,
							CORE_FUZZ_TA_SLOTS);
					else
						write_u16(header + 5,
							output_boundaries[random_below(rng,
								sizeof(output_boundaries) /
								sizeof(output_boundaries[0]))]);
				} else if (header[0] == CORE_FUZZ_TA_AUTHENC_INIT) {
					if (random_below(rng, 2))
						header[2] = tag_boundaries[random_below(rng,
							sizeof(tag_boundaries) /
							sizeof(tag_boundaries[0]))];
					else
						write_u16(header + 5,
							(uint16_t)next_random(rng));
				} else if (header[0] == CORE_FUZZ_TA_AUTHENC_ENC_FINAL ||
					 header[0] == CORE_FUZZ_TA_AUTHENC_DEC_FINAL) {
					if (random_below(rng, 2))
						header[2] = tag_boundaries[random_below(rng,
							sizeof(tag_boundaries) /
							sizeof(tag_boundaries[0]))];
					else
						write_u16(header + 5,
							output_boundaries[random_below(rng,
								sizeof(output_boundaries) /
								sizeof(output_boundaries[0]))]);
				} else if (header[0] == CORE_FUZZ_TA_ASYMM_VERIFY) {
					header[2] = random_below(rng, 2);
					write_u16(header + 5,
						  (uint16_t)random_below(rng,
								   data_size + 1));
				} else if (header[0] == CORE_FUZZ_TA_CIPHER_UPDATE ||
					 header[0] == CORE_FUZZ_TA_CIPHER_FINAL ||
					 header[0] == CORE_FUZZ_TA_RANDOM ||
					 header[0] == CORE_FUZZ_TA_AUTHENC_UPDATE_PAYLOAD ||
					 header[0] == CORE_FUZZ_TA_ASYMM_OPERATE)
					write_u16(header + 5,
						output_boundaries[random_below(rng,
							sizeof(output_boundaries) /
							sizeof(output_boundaries[0]))]);
				else
					write_u16(header + 5,
						(uint16_t)next_random(rng));
				break;
			case 3:
				memcpy(scratch, data, data_size);
				if (!data_size) {
					scratch[0] = 0;
					data_size = 1;
				}
				scratch[random_below(rng, data_size)] ^=
					1U << random_below(rng, 8);
				data = scratch;
				break;
			case 4: {
				size_t new_size = payload_boundaries[
					random_below(rng,
						sizeof(payload_boundaries) /
						sizeof(payload_boundaries[0]))];
				size_t copied = data_size < new_size ?
					data_size : new_size;

				memcpy(scratch, data, copied);
				for (size_t j = copied; j < new_size; j++)
					scratch[j] = (uint8_t)next_random(rng);
				data = scratch;
				data_size = new_size;
				break;
			}
			default:
				break;
			}
		}
		if (!append_op(out, &size, header, data, data_size))
			return false;
		if (action == 7 && i == target &&
		    !append_op(out, &size, header, data, data_size))
			return false;
	}
	if (action == 5 && target == count &&
	    !append_new_op(out, &size, rng, -1))
		return false;
	if (action == 5 || action == 7 || action == 9)
		out[5] = count + 1;
	else if (action == 6)
		out[5] = count - 1;
	*out_size = size;
	return true;
}

static void mutate_raw(const uint8_t *input, size_t input_size,
		       uint8_t *out, size_t *out_size, struct rng *rng)
{
	size_t action = random_below(rng, 5);
	size_t size = input_size;
	size_t offset = 0;

	memcpy(out, input, input_size);
	if (!size)
		action = 2;
	switch (action) {
	case 0:
		offset = random_below(rng, size);
		out[offset] ^= 1U << random_below(rng, 8);
		break;
	case 1:
		offset = random_below(rng, size);
		out[offset] = (uint8_t)next_random(rng);
		break;
	case 2:
		if (size < CORE_FUZZ_TA_MAX_INPUT) {
			offset = random_below(rng, size + 1);
			memmove(out + offset + 1, out + offset, size - offset);
			out[offset] = (uint8_t)next_random(rng);
			size++;
		}
		break;
	case 3:
		offset = random_below(rng, size);
		memmove(out + offset, out + offset + 1, size - offset - 1);
		size--;
		break;
	default:
		size = random_below(rng, size);
		break;
	}
	*out_size = size;
}

static void mutate(const struct input *parent, uint8_t *out,
		   size_t *out_size, struct rng *rng,
		   bool hopper_enabled)
{
	if (!random_below(rng, 5)) {
		mutate_raw(parent->bytes, parent->size, out, out_size, rng);
		return;
	}
	for (size_t attempt = 0; attempt < MAX_MUTATION_ATTEMPTS;
	     attempt++) {
		if (mutate_structured(parent->bytes, parent->size, out,
				      out_size, rng, hopper_enabled) &&
		    (*out_size != parent->size ||
		     memcmp(out, parent->bytes, *out_size)))
			return;
	}
	mutate_raw(parent->bytes, parent->size, out, out_size, rng);
}

/* Keep the learned producer/consumer sequence intact while changing data. */
static bool mutate_learned(const struct input *parent, uint8_t *out,
			   size_t *out_size, struct rng *rng)
{
	struct parsed_input parsed = { 0 };
	size_t choices[CORE_FUZZ_TA_MAX_OPS];
	size_t count = 0;
	const struct op_view *op = NULL;

	if (!parse_input(parent->bytes, parent->size, &parsed))
		return false;
	for (size_t i = 0; i < parsed.count; i++)
		if (parsed.ops[i].data_size ||
		    parsed.ops[i].header[0] == CORE_FUZZ_TA_FINAL)
			choices[count++] = i;
	if (!count)
		return false;
	op = &parsed.ops[choices[random_below(rng, count)]];
	memcpy(out, parent->bytes, parent->size);
	*out_size = parent->size;
	if (op->data_size) {
		size_t offset = (size_t)(op->data - parent->bytes) +
			random_below(rng, op->data_size);

		out[offset] ^= 1U << random_below(rng, 8);
	} else {
		static const uint16_t capacities[] = { 0, 1, 31, 32, 33, 64 };
		size_t offset = (size_t)(op->header - parent->bytes) + 5;
		uint16_t previous = read_u16(out + offset);
		uint16_t value = capacities[random_below(rng,
			ARRAY_SIZE(capacities))];

		write_u16(out + offset, value == previous ?
				 (uint16_t)(previous == 32 ? 31 : 32) : value);
	}
	return true;
}

static bool corpus_add(struct corpus *corpus, const uint8_t *bytes,
		       size_t size)
{
	uint8_t *copy = NULL;

	if (corpus->count == MAX_CORPUS_ENTRIES)
		return false;
	copy = malloc(size ? size : 1);
	if (!copy)
		return false;
	if (size)
		memcpy(copy, bytes, size);
	corpus->entries[corpus->count].bytes = copy;
	corpus->entries[corpus->count].size = size;
	corpus->count++;
	return true;
}

static bool corpus_find(const struct corpus *corpus, const uint8_t *bytes,
			 size_t size, size_t *index)
{
	for (size_t i = 0; i < corpus->count; i++) {
		if (corpus->entries[i].size == size &&
		    (!size || !memcmp(corpus->entries[i].bytes, bytes, size))) {
			*index = i;
			return true;
		}
	}
	return false;
}

static void corpus_free(struct corpus *corpus)
{
	for (size_t i = 0; i < corpus->count; i++)
		free(corpus->entries[i].bytes);
}

static void record_opcode_outcomes(const struct execution *execution)
{
	const uint8_t *response = execution->response;
	size_t count = 0;

	if (execution->result != TEEC_SUCCESS ||
	    execution->response_size < CORE_FUZZ_TA_OUTPUT_HEADER_SIZE ||
	    memcmp(response, "FZR2", 4) ||
	    response[4] != CORE_FUZZ_TA_VERSION)
		return;
	count = response[5];
	if (count > CORE_FUZZ_TA_MAX_OPS ||
	    execution->response_size < CORE_FUZZ_TA_OUTPUT_HEADER_SIZE +
		count * CORE_FUZZ_TA_RESULT_SIZE)
		return;
	for (size_t i = 0; i < count; i++) {
		const uint8_t *record = response +
			CORE_FUZZ_TA_OUTPUT_HEADER_SIZE +
			i * CORE_FUZZ_TA_RESULT_SIZE;
		uint8_t opcode = record[4];

		if (opcode < CORE_FUZZ_TA_ALLOC ||
		    opcode > CORE_FUZZ_TA_ASYMM_VERIFY)
			continue;
		opcode_calls[opcode]++;
		if (read_u32(record) == TEEC_SUCCESS)
			opcode_success[opcode]++;
	}
}

static void execute_input(TEEC_Context *context, const uint8_t *input,
			  size_t input_size, int target_index,
			  uint8_t target_opcode, struct execution *execution)
{
	const TEEC_UUID uuid = CORE_FUZZ_TA_UUID;
	TEEC_Session session = { 0 };
	TEEC_Operation operation = { 0 };
	uint32_t origin = 0;

	memset(execution, 0, sizeof(*execution));
	execution->target_index = target_index;
	execution->target_opcode = target_opcode;
	execution->result = TEEC_OpenSession(context, &session, &uuid,
		TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	execution->origin = origin;
	if (execution->result != TEEC_SUCCESS)
		return;
	execution->session_opened = true;
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
		target_index < 0 ? TEEC_NONE : TEEC_VALUE_INPUT);
	operation.params[0].tmpref.buffer = (void *)input;
	operation.params[0].tmpref.size = input_size;
	operation.params[1].tmpref.buffer = execution->response;
	operation.params[1].tmpref.size = sizeof(execution->response);
	operation.params[2].tmpref.buffer = execution->coverage;
	operation.params[2].tmpref.size = sizeof(execution->coverage);
	if (target_index >= 0)
		operation.params[3].value.a = (uint32_t)target_index;
	origin = 0;
	ta_invocations++;
	execution->result = TEEC_InvokeCommand(&session, CORE_FUZZ_TA_CMD_RUN,
		&operation, &origin);
	execution->origin = origin;
	execution->coverage_valid =
		execution->result == TEEC_SUCCESS &&
		operation.params[2].tmpref.size == COVERAGE_SIZE;
	if (execution->result == TEEC_SUCCESS &&
	    operation.params[1].tmpref.size <= sizeof(execution->response))
		execution->response_size = operation.params[1].tmpref.size;
	record_opcode_outcomes(execution);
	TEEC_CloseSession(&session);
}

/* The outer QEMU watchdog can recover this input if the secure core hangs
 * before TEEC_InvokeCommand returns. Each rename publishes a complete file.
 * current.meta records whether this invocation used whole-sequence coverage or
 * targeted coverage; both files are ready before entering the secure world.
 */
static bool write_current(const char *run_dir, const uint8_t *input,
			  size_t input_size, int target_index)
{
	char temporary[PATH_CAP];
	char current[PATH_CAP];
	char meta_temporary[PATH_CAP];
	char meta_current[PATH_CAP];
	FILE *file = NULL;

	if ((size_t)snprintf(temporary, sizeof(temporary), "%s/current.bin.tmp",
			     run_dir) >= sizeof(temporary) ||
	    (size_t)snprintf(current, sizeof(current), "%s/current.bin",
			     run_dir) >= sizeof(current) ||
	    (size_t)snprintf(meta_temporary, sizeof(meta_temporary),
			     "%s/current.meta.tmp", run_dir) >=
			     sizeof(meta_temporary) ||
	    (size_t)snprintf(meta_current, sizeof(meta_current),
			     "%s/current.meta", run_dir) >= sizeof(meta_current))
		return false;
	file = fopen(temporary, "wb");
	if (!file)
		return false;
	if (input_size && fwrite(input, 1, input_size, file) != input_size) {
		fclose(file);
		return false;
	}
	if (fclose(file) || rename(temporary, current))
		return false;
	file = fopen(meta_temporary, "w");
	if (!file)
		return false;
	if (fprintf(file, "target_index=%d\n", target_index) < 0) {
		fclose(file);
		return false;
	}
	if (fclose(file))
		return false;
	return !rename(meta_temporary, meta_current);
}

static bool execute_recorded(TEEC_Context *context, const char *run_dir,
			     const uint8_t *input, size_t input_size,
			     int target_index, uint8_t target_opcode,
			     struct execution *execution)
{
	if (!write_current(run_dir, input, input_size, target_index))
		return false;
	execute_input(context, input, input_size, target_index, target_opcode,
		      execution);
	return true;
}

static size_t coverage_new(void *opaque, const struct execution *a,
			   const struct execution *b)
{
	const struct coverage_state *state = opaque;
	size_t added = 0;

	if (a->target_index >= 0 || b->target_index >= 0 ||
	    !a->coverage_valid || !b->coverage_valid)
		return 0;
	for (size_t i = 0; i < COVERAGE_SIZE; i++)
		if (a->coverage[i] && b->coverage[i] && !state->seen[i])
			added++;
	return added;
}

static void coverage_commit(void *opaque, const struct execution *a,
			    const struct execution *b)
{
	struct coverage_state *state = opaque;

	if (a->target_index >= 0 || b->target_index >= 0 ||
	    !a->coverage_valid || !b->coverage_valid)
		return;
	for (size_t i = 0; i < COVERAGE_SIZE; i++) {
		if (a->coverage[i] && b->coverage[i] && !state->seen[i]) {
			state->seen[i] = 1;
			state->total++;
		}
	}
}

static size_t target_coverage_new(void *opaque, const struct execution *a,
				  const struct execution *b)
{
	const struct target_coverage_state *state = opaque;
	size_t added = 0;
	uint8_t opcode = a->target_opcode;

	if (a->target_index < 0 || b->target_index < 0 ||
	    a->target_index != b->target_index ||
	    opcode != b->target_opcode || opcode < CORE_FUZZ_TA_ALLOC ||
	    opcode > CORE_FUZZ_TA_ASYMM_VERIFY || !a->coverage_valid ||
	    !b->coverage_valid)
		return 0;
	for (size_t i = 0; i < COVERAGE_SIZE; i++)
		if (a->coverage[i] && b->coverage[i] && !state->seen[opcode][i])
			added++;
	return added;
}

static void target_coverage_commit(void *opaque,
				   const struct execution *a,
				   const struct execution *b)
{
	struct target_coverage_state *state = opaque;
	uint8_t opcode = a->target_opcode;

	if (a->target_index < 0 || b->target_index < 0 ||
	    a->target_index != b->target_index ||
	    opcode != b->target_opcode || opcode < CORE_FUZZ_TA_ALLOC ||
	    opcode > CORE_FUZZ_TA_ASYMM_VERIFY || !a->coverage_valid ||
	    !b->coverage_valid)
		return;
	for (size_t i = 0; i < COVERAGE_SIZE; i++) {
		if (a->coverage[i] && b->coverage[i] &&
		    !state->seen[opcode][i]) {
			state->seen[opcode][i] = 1;
			state->total++;
		}
	}
}

static bool feedback_register(struct feedback *feedback,
			      const struct feedback_criterion *criterion)
{
	if (feedback->count == MAX_CRITERIA)
		return false;
	feedback->criteria[feedback->count++] = *criterion;
	return true;
}

static size_t feedback_new(const struct feedback *feedback,
			   const struct execution *a,
			   const struct execution *b)
{
	size_t added = 0;

	for (size_t i = 0; i < feedback->count; i++)
		added += feedback->criteria[i].new_features(
			feedback->criteria[i].state, a, b);
	return added;
}

static void feedback_commit(const struct feedback *feedback,
			    const struct execution *a,
			    const struct execution *b)
{
	for (size_t i = 0; i < feedback->count; i++)
		feedback->criteria[i].commit(feedback->criteria[i].state, a, b);
}

static bool mkdir_if_missing(const char *path)
{
	return !mkdir(path, 0755) || errno == EEXIST;
}

static bool create_run_dir(const char *output_dir, char *run_dir,
			   size_t capacity, bool hopper_enabled)
{
	char path[PATH_CAP];

	if (!mkdir_if_missing(output_dir) ||
	    (size_t)snprintf(run_dir, capacity, "%s/run-XXXXXX", output_dir) >=
		capacity || !mkdtemp(run_dir))
		return false;
	if ((size_t)snprintf(path, sizeof(path), "%s/corpus", run_dir) >=
		sizeof(path) || !mkdir_if_missing(path))
		return false;
	if ((size_t)snprintf(path, sizeof(path), "%s/crashes", run_dir) >=
		sizeof(path) || !mkdir_if_missing(path))
		return false;
	if (!hopper_enabled)
		return true;
	if ((size_t)snprintf(path, sizeof(path), "%s/target", run_dir) >=
		sizeof(path) || !mkdir_if_missing(path))
		return false;
	if ((size_t)snprintf(path, sizeof(path), "%s/learned", run_dir) >=
		sizeof(path) || !mkdir_if_missing(path))
		return false;
	if ((size_t)snprintf(path, sizeof(path), "%s/assembled", run_dir) >=
		sizeof(path) || !mkdir_if_missing(path))
		return false;
	return true;
}

static bool save_artifact(const char *run_dir, const char *category,
			  uint64_t id, const uint8_t *input, size_t size,
			  uint64_t iteration, size_t parent,
			  const struct execution *execution,
			  size_t new_features)
{
	char path[PATH_CAP];
	FILE *file = NULL;

	if ((size_t)snprintf(path, sizeof(path), "%s/%s/id-%08" PRIu64 ".bin",
		     run_dir, category, id) >= sizeof(path))
		return false;
	file = fopen(path, "wb");
	if (!file)
		return false;
	if (size && fwrite(input, 1, size, file) != size) {
		fclose(file);
		return false;
	}
	if (fclose(file))
		return false;
	if ((size_t)snprintf(path, sizeof(path), "%s/%s/id-%08" PRIu64 ".txt",
		     run_dir, category, id) >= sizeof(path))
		return false;
	file = fopen(path, "w");
	if (!file)
		return false;
	fprintf(file, "iteration=%" PRIu64 "\nparent_index=%zu\n"
		"input_size=%zu\ninvoke_result=0x%08" PRIx32 "\n"
		"origin=%" PRIu32 "\nnew_features=%zu\n"
		"coverage_format=%u\ncoverage_map_bytes=%u\n"
		"coverage_valid=%u\ncoverage_scope=%s\n"
		"target_index=%d\ntarget_opcode=%u\n",
		iteration, parent, size, (uint32_t)execution->result,
		execution->origin, new_features,
		PTA_CORE_FUZZ_COV_FORMAT_VERSION, COVERAGE_SIZE,
		execution->result == TEEC_SUCCESS && execution->coverage_valid,
		execution->target_index < 0 ? "whole" : "target",
		execution->target_index, execution->target_opcode);
	if (fclose(file))
		return false;
	if (execution->result != TEEC_SUCCESS || !execution->coverage_valid)
		return true;
	if ((size_t)snprintf(path, sizeof(path), "%s/%s/id-%08" PRIu64 ".cov",
		     run_dir, category, id) >= sizeof(path))
		return false;
	file = fopen(path, "wb");
	if (!file)
		return false;
	if (fwrite(execution->coverage, 1, COVERAGE_SIZE, file) !=
	    COVERAGE_SIZE) {
		fclose(file);
		return false;
	}
	return !fclose(file);
}

static bool save_assembly_sample(const char *run_dir, uint64_t iteration,
				 size_t parent, size_t template_index,
				 int target_index, const uint8_t *input,
				 size_t size,
				 const struct execution *execution)
{
	char path[PATH_CAP];
	FILE *file = NULL;

	if (!save_artifact(run_dir, "assembled", iteration, input, size,
			   iteration, parent, execution, 0) ||
	    (size_t)snprintf(path, sizeof(path),
		"%s/assembled/id-%08" PRIu64 ".txt", run_dir,
		iteration) >= sizeof(path))
		return false;
	file = fopen(path, "a");
	if (!file)
		return false;
	fprintf(file, "assembly_source_parent=%zu\n"
		"assembly_template_parent=%zu\nassembly_target_index=%d\n",
		parent, template_index, target_index);
	return !fclose(file);
}

static int seed_filter(const struct dirent *entry)
{
	size_t length = strlen(entry->d_name);

	return length > 4 && !strcmp(entry->d_name + length - 4, ".bin");
}

static bool read_seed(const char *path, uint8_t *bytes, size_t *size)
{
	FILE *file = fopen(path, "rb");
	size_t n = 0;

	if (!file)
		return false;
	n = fread(bytes, 1, CORE_FUZZ_TA_MAX_INPUT + 1, file);
	if (ferror(file) || n > CORE_FUZZ_TA_MAX_INPUT) {
		fclose(file);
		return false;
	}
	if (fclose(file))
		return false;
	*size = n;
	return true;
}

static bool is_target_dead(const struct execution *execution)
{
	return execution->result == TEEC_ERROR_TARGET_DEAD;
}

static const uint8_t *target_record(const struct execution *execution)
{
	size_t offset = 0;

	if (execution->result != TEEC_SUCCESS || !execution->coverage_valid ||
	    execution->target_index < 0 ||
	    execution->target_index >= (int)CORE_FUZZ_TA_MAX_OPS ||
	    execution->response_size < CORE_FUZZ_TA_OUTPUT_HEADER_SIZE ||
	    memcmp(execution->response, "FZR2", 4) ||
	    execution->response[4] != CORE_FUZZ_TA_VERSION ||
	    execution->response[5] <= execution->target_index)
		return NULL;
	offset = CORE_FUZZ_TA_OUTPUT_HEADER_SIZE +
		(size_t)execution->target_index * CORE_FUZZ_TA_RESULT_SIZE;
	if (offset > execution->response_size ||
	    execution->response_size - offset < CORE_FUZZ_TA_RESULT_SIZE)
		return NULL;
	if (execution->response[offset + 4] != execution->target_opcode)
		return NULL;
	return execution->response + offset;
}

static bool output_step_status(const struct execution *execution,
			       int step_index, uint8_t opcode,
			       uint32_t *status)
{
	size_t offset = 0;

	if (execution->result != TEEC_SUCCESS || step_index < 0 ||
	    step_index >= (int)CORE_FUZZ_TA_MAX_OPS ||
	    execution->response_size < CORE_FUZZ_TA_OUTPUT_HEADER_SIZE ||
	    memcmp(execution->response, "FZR2", 4) ||
	    execution->response[4] != CORE_FUZZ_TA_VERSION ||
	    execution->response[5] <= step_index)
		return false;
	offset = CORE_FUZZ_TA_OUTPUT_HEADER_SIZE +
		(size_t)step_index * CORE_FUZZ_TA_RESULT_SIZE;
	if (offset > execution->response_size ||
	    execution->response_size - offset < CORE_FUZZ_TA_RESULT_SIZE ||
	    execution->response[offset + 4] != opcode)
		return false;
	*status = read_u32(execution->response + offset);
	return true;
}

static bool target_record_equal(const struct execution *a,
				const struct execution *b)
{
	const uint8_t *a_record = target_record(a);
	const uint8_t *b_record = target_record(b);
	size_t stable_size = CORE_FUZZ_TA_RESULT_SIZE;

	if (!a_record || !b_record || a->target_opcode != b->target_opcode)
		return false;
	/* Random bytes and RSA encryption output can vary between replays. */
	if (a->target_opcode == CORE_FUZZ_TA_RANDOM ||
	    a->target_opcode == CORE_FUZZ_TA_ASYMM_OPERATE)
		stable_size = CORE_FUZZ_TA_RESULT_SIZE -
			CORE_FUZZ_TA_RESULT_DATA_SIZE;
	return !memcmp(a_record, b_record, stable_size);
}

static bool target_observation_equal(const struct execution *a,
				     const struct execution *b)
{
	return target_record_equal(a, b) &&
	       !memcmp(a->coverage, b->coverage, COVERAGE_SIZE);
}

static size_t collect_targets(const uint8_t *input, size_t size,
			      uint8_t targets[CORE_FUZZ_TA_MAX_OPS])
{
	struct parsed_input parsed = { 0 };
	size_t count = 0;

	if (size > CORE_FUZZ_TA_MAX_INPUT ||
	    !parse_input(input, size, &parsed))
		return 0;
	for (size_t i = 1; i < parsed.count; i++) {
		uint8_t opcode = parsed.ops[i].header[0];

		if (opcode >= CORE_FUZZ_TA_INIT &&
		    opcode <= CORE_FUZZ_TA_ASYMM_VERIFY)
			targets[count++] = i;
	}
	return count;
}

static bool keep_through_target(const uint8_t *input, size_t size,
				int target_index, uint8_t *out,
				size_t *out_size)
{
	struct parsed_input parsed = { 0 };
	const struct op_view *target = NULL;

	if (!parse_input(input, size, &parsed) || target_index < 0 ||
	    target_index >= parsed.count)
		return false;
	target = &parsed.ops[target_index];
	*out_size = (size_t)(target->data - input) + target->data_size;
	memcpy(out, input, *out_size);
	out[5] = target_index + 1;
	return true;
}

static bool remove_op(const uint8_t *input, size_t size, size_t index,
		      uint8_t *out, size_t *out_size)
{
	struct parsed_input parsed = { 0 };
	size_t start = 0;
	size_t end = 0;

	if (!parse_input(input, size, &parsed) || index >= parsed.count)
		return false;
	start = (size_t)(parsed.ops[index].header - input);
	end = (size_t)(parsed.ops[index].data - input) +
		parsed.ops[index].data_size;
	memcpy(out, input, start);
	memcpy(out + start, input + end, size - end);
	*out_size = size - (end - start);
	out[5] = parsed.count - 1;
	return true;
}

enum probe_status {
	PROBE_OK,
	PROBE_SKIP,
	PROBE_ERROR = 2,
	PROBE_CRASH = 3,
};

static enum probe_status execute_target_checked(TEEC_Context *context,
		const char *run_dir, const uint8_t *input, size_t size,
		int target_index, uint8_t target_opcode, uint64_t iteration,
		size_t parent, uint64_t *artifact_id,
		struct execution *execution)
{
	if (!execute_recorded(context, run_dir, input, size, target_index,
			      target_opcode, execution))
		return PROBE_ERROR;
	if (is_target_dead(execution)) {
		if (!save_artifact(run_dir, "crashes", (*artifact_id)++, input,
				   size, iteration, parent, execution, 0))
			fprintf(stderr, "cannot save target-probe crash input\n");
		return PROBE_CRASH;
	}
	if (!execution->session_opened)
		return PROBE_ERROR;
	if (!target_record(execution))
		return PROBE_SKIP;
	return PROBE_OK;
}

static bool save_learned_relations(const char *run_dir, uint64_t id,
				   const uint8_t *input, size_t size,
				   const uint8_t evidence[CORE_FUZZ_TA_MAX_OPS],
				   int target_index)
{
	struct parsed_input parsed = { 0 };
	char path[PATH_CAP];
	FILE *file = NULL;
	uint8_t target_slot = 0;

	if (!parse_input(input, size, &parsed) ||
	    target_index >= parsed.count ||
	    (size_t)snprintf(path, sizeof(path),
		"%s/learned/id-%08" PRIu64 ".txt", run_dir, id) >=
		sizeof(path))
		return false;
	file = fopen(path, "a");
	if (!file)
		return false;
	target_slot = parsed.ops[target_index].header[1];
	fprintf(file, "relation_kind=observed_target_effect\n");
	for (int i = 0; i < target_index; i++) {
		if (!evidence[i])
			continue;
		fprintf(file, "predecessor=%d,opcode=%u,slot=%u,"
			"same_slot=%u,coverage_changed=%u,record_changed=%u\n",
			i, parsed.ops[i].header[0], parsed.ops[i].header[1],
			parsed.ops[i].header[1] == target_slot,
			!!(evidence[i] & EFFECT_COVERAGE),
			!!(evidence[i] & EFFECT_RECORD));
	}
	return !fclose(file);
}

/* A target path is kept only after a stable replay. Then each predecessor is
 * removed and replayed to test whether it changes the target observation.
 */
static int learn_target(TEEC_Context *context, const char *run_dir,
			const uint8_t *candidate, size_t size, int target_index,
			uint64_t iteration, size_t parent,
			const struct feedback *feedback, struct corpus *corpus,
			struct learned_pool *learned, uint64_t *artifact_id)
{
	struct parsed_input parsed = { 0 };
	struct execution first = { 0 };
	struct execution second = { 0 };
	struct execution probe_a = { 0 };
	struct execution probe_b = { 0 };
	struct execution artifact_execution = { 0 };
	uint8_t witness[CORE_FUZZ_TA_MAX_INPUT];
	uint8_t probe[CORE_FUZZ_TA_MAX_INPUT];
	uint8_t evidence[CORE_FUZZ_TA_MAX_OPS] = { 0 };
	uint8_t opcode = 0;
	size_t witness_size = 0;
	size_t new_features = 0;
	size_t critical_count = 0;
	size_t corpus_index = 0;
	size_t probes = 0;
	bool have_corpus_index = false;
	bool assemblable = false;
	int witness_target = target_index;
	enum probe_status status = PROBE_OK;
	const char *category = NULL;

	if (!parse_input(candidate, size, &parsed) || target_index < 1 ||
	    target_index >= parsed.count)
		return 0;
	opcode = parsed.ops[target_index].header[0];
	status = execute_target_checked(context, run_dir, candidate, size,
		target_index, opcode, iteration, parent, artifact_id, &first);
	if (status == PROBE_ERROR || status == PROBE_CRASH)
		return status;
	if (status == PROBE_SKIP || !feedback_new(feedback, &first, &first))
		return 0;
	status = execute_target_checked(context, run_dir, candidate, size,
		target_index, opcode, iteration, parent, artifact_id, &second);
	if (status == PROBE_ERROR || status == PROBE_CRASH)
		return status;
	if (status == PROBE_SKIP || !target_observation_equal(&first, &second))
		return 0;
	new_features = feedback_new(feedback, &first, &second);
	if (!new_features)
		return 0;

	if (!keep_through_target(candidate, size, target_index, witness,
				 &witness_size))
		return PROBE_ERROR;
	/* Truncation removes only calls after the target, but verify that the
	 * target-only map and result remain unchanged before minimizing.
	 */
	if (witness_size != size) {
		status = execute_target_checked(context, run_dir, witness,
			witness_size, witness_target, opcode, iteration, parent,
			artifact_id, &probe_a);
		if (status == PROBE_ERROR || status == PROBE_CRASH)
			return status;
		if (status != PROBE_OK ||
		    !target_observation_equal(&first, &probe_a)) {
			memcpy(witness, candidate, size);
			witness_size = size;
		}
	}

	for (int i = witness_target - 1; i >= 0 && probes <
	     MAX_PREFIX_PROBES; i--) {
		size_t probe_size = 0;

		probes++;
		if (!remove_op(witness, witness_size, i, probe, &probe_size))
			return PROBE_ERROR;
		status = execute_target_checked(context, run_dir, probe,
			probe_size, witness_target - 1, opcode, iteration,
			parent, artifact_id, &probe_a);
		if (status == PROBE_ERROR || status == PROBE_CRASH)
			return status;
		if (status == PROBE_SKIP)
			continue;
		status = execute_target_checked(context, run_dir, probe,
			probe_size, witness_target - 1, opcode, iteration,
			parent, artifact_id, &probe_b);
		if (status == PROBE_ERROR || status == PROBE_CRASH)
			return status;
		if (status == PROBE_SKIP ||
		    !target_observation_equal(&probe_a, &probe_b))
			continue;
		if (target_observation_equal(&first, &probe_a)) {
			memcpy(witness, probe, probe_size);
			witness_size = probe_size;
			witness_target--;
			memmove(evidence + i, evidence + i + 1,
				(witness_target - i) * sizeof(evidence[0]));
		} else {
			evidence[i] =
				(memcmp(first.coverage, probe_a.coverage,
					COVERAGE_SIZE) ? EFFECT_COVERAGE : 0) |
				(!target_record_equal(&first, &probe_a) ?
				 EFFECT_RECORD : 0);
			critical_count++;
		}
	}
	category = critical_count ? "learned" : "target";
	artifact_execution = first;
	artifact_execution.target_index = witness_target;
	if (!save_artifact(run_dir, category, *artifact_id, witness,
			   witness_size, iteration, parent,
			   &artifact_execution, new_features))
		return PROBE_ERROR;
	if (critical_count &&
	    !save_learned_relations(run_dir, *artifact_id, witness,
				    witness_size, evidence, witness_target))
		return PROBE_ERROR;
	(*artifact_id)++;
	have_corpus_index = corpus_find(corpus, witness, witness_size,
					&corpus_index);
	if (!have_corpus_index && corpus->count < MAX_CORPUS_ENTRIES) {
		if (!corpus_add(corpus, witness, witness_size))
			return PROBE_ERROR;
		corpus_index = corpus->count - 1;
		have_corpus_index = true;
	}
	if (critical_count) {
		struct parsed_input reduced = { 0 };
		uint8_t target_slot = 0;

		if (!parse_input(witness, witness_size, &reduced) ||
		    witness_target >= reduced.count)
			return PROBE_ERROR;
		target_slot = reduced.ops[witness_target].header[1];
		/* The existing assembler rebinds only one state slot. Object
		 * operations and keyed states also depend on a second slot.
		 */
		assemblable = witness_target > 0 &&
			      opcode <= CORE_FUZZ_TA_FREE;
		for (int i = 0; i < witness_target; i++)
			if (!evidence[i] ||
			    reduced.ops[i].header[1] != target_slot ||
			    reduced.ops[i].header[0] > CORE_FUZZ_TA_FREE ||
		    (reduced.ops[i].header[0] == CORE_FUZZ_TA_ALLOC &&
		     reduced.ops[i].header[2] >= 2))
				assemblable = false;
	}
	if (critical_count && have_corpus_index &&
	    learned->count < MAX_LEARNED_ENTRIES) {
		bool already_learned = false;

		for (size_t i = 0; i < learned->count; i++)
			if (learned->entries[i].corpus_index == corpus_index &&
			    learned->entries[i].target_index == witness_target &&
			    learned->entries[i].target_opcode == opcode)
				already_learned = true;
		if (!already_learned) {
			struct learned_entry *entry =
				&learned->entries[learned->count++];

			entry->corpus_index = corpus_index;
			entry->target_index = witness_target;
			entry->target_opcode = opcode;
			entry->assemblable = assemblable;
			if (assemblable)
				learned->assemblable++;
		}
	}
	learned->relations += critical_count;
	feedback_commit(feedback, &first, &second);
	printf("FUZZ_TARGET ITER=%" PRIu64 " OPCODE=%u NEW=%zu "
	       "CRITICAL=%zu LEARNED=%zu\n", iteration, opcode,
	       new_features, critical_count, learned->count);
	fflush(stdout);
	return 0;
}

/* Reuse verified predecessors from one corpus program with a target call
 * taken from another. This is a new program, not a mutation of the saved
 * witness. Cross-slot effects are kept as observations but not grafted.
 */
static bool assemble_learned(const struct input *parent,
			     size_t parent_index, const struct corpus *corpus,
			     const struct learned_pool *learned, uint8_t *out,
			     size_t *out_size, int *target_index,
			     uint8_t *target_opcode, size_t *template_index,
			     struct rng *rng)
{
	struct parsed_input source = { 0 };
	uint8_t targets[CORE_FUZZ_TA_MAX_OPS];
	size_t target_count = 0;

	if (!learned->assemblable ||
	    !parse_input(parent->bytes, parent->size, &source))
		return false;
	for (size_t i = 0; i < source.count; i++) {
		bool single_slot_prefix = true;

		for (size_t k = 0; k <= i; k++)
			if (source.ops[k].header[0] > CORE_FUZZ_TA_FREE ||
			    (source.ops[k].header[0] == CORE_FUZZ_TA_ALLOC &&
			     source.ops[k].header[2] >= 2))
				single_slot_prefix = false;
		if (!single_slot_prefix)
			continue;
		for (size_t j = 0; j < learned->count; j++) {
			if (learned->entries[j].assemblable &&
			    learned->entries[j].target_opcode ==
					source.ops[i].header[0] &&
			    learned->entries[j].corpus_index != parent_index) {
				targets[target_count++] = i;
				break;
			}
		}
	}
	if (!target_count)
		return false;
	for (size_t attempt = 0; attempt < MAX_MUTATION_ATTEMPTS;
	     attempt++) {
		const struct op_view *target =
			&source.ops[targets[random_below(rng, target_count)]];
		const struct learned_entry *choice = NULL;
		struct parsed_input donor = { 0 };
		size_t matching = 0;
		size_t size = CORE_FUZZ_TA_INPUT_HEADER_SIZE;
		uint8_t slot = target->header[1];
		bool prefix_complete = true;

		for (size_t j = 0; j < learned->count; j++) {
			const struct learned_entry *entry = &learned->entries[j];

			if (!entry->assemblable ||
			    entry->target_opcode != target->header[0] ||
			    entry->corpus_index == parent_index)
				continue;
			matching++;
			if (!random_below(rng, matching))
				choice = entry;
		}
		if (!choice || !parse_input(
			corpus->entries[choice->corpus_index].bytes,
			corpus->entries[choice->corpus_index].size, &donor) ||
		    choice->target_index >= donor.count ||
		    donor.ops[choice->target_index].header[0] !=
				choice->target_opcode)
			continue;
		memcpy(out, corpus->entries[choice->corpus_index].bytes,
		       CORE_FUZZ_TA_INPUT_HEADER_SIZE);
		for (size_t i = 0; i < choice->target_index; i++) {
			uint8_t header[CORE_FUZZ_TA_OP_HEADER_SIZE];
			const struct op_view *op = &donor.ops[i];

			memcpy(header, op->header, sizeof(header));
			header[1] = slot;
			if (!append_op(out, &size, header, op->data,
				       op->data_size)) {
				prefix_complete = false;
				break;
			}
		}
		if (!prefix_complete ||
		    !append_op(out, &size, target->header, target->data,
			       target->data_size))
			continue;
		out[5] = choice->target_index + 1;
		if (!parse_input(out, size, &donor) ||
		    (size == parent->size &&
		     !memcmp(out, parent->bytes, size)) ||
		    (size == corpus->entries[choice->corpus_index].size &&
		     !memcmp(out,
			corpus->entries[choice->corpus_index].bytes, size)))
			continue;
		*out_size = size;
		*target_index = choice->target_index;
		*target_opcode = target->header[0];
		*template_index = choice->corpus_index;
		return true;
	}
	return false;
}

static void generate_case(struct hopper_module *hopper,
			  const struct corpus *corpus, struct rng *rng,
			  uint8_t *candidate, struct generated_case *generated,
			  uint64_t iteration)
{
	bool learned_parent = hopper->enabled && hopper->learned.count &&
		!random_below(rng, 4);

	memset(generated, 0, sizeof(*generated));
	generated->assembled_target = -1;
	generated->parent = learned_parent ?
		hopper->learned.entries[random_below(rng,
			hopper->learned.count)].corpus_index :
		random_below(rng, corpus->count);
	if (hopper->enabled && hopper->learned.assemblable &&
	    !random_below(rng, 4)) {
		hopper->assembly_attempts++;
		generated->assembled = assemble_learned(
			&corpus->entries[generated->parent], generated->parent,
			corpus, &hopper->learned, candidate,
			&generated->size, &generated->assembled_target,
			&generated->assembled_opcode,
			&generated->template_index, rng);
		if (generated->assembled) {
			hopper->assemblies++;
			printf("FUZZ_ASSEMBLED ITER=%" PRIu64
			       " PARENT=%zu TEMPLATE=%zu TARGET=%d\n",
			       iteration, generated->parent,
			       generated->template_index,
			       generated->assembled_target);
			fflush(stdout);
		}
	}
	if (!generated->assembled) {
		if (!learned_parent || random_below(rng, 2) ||
		    !mutate_learned(&corpus->entries[generated->parent],
				    candidate, &generated->size, rng))
			mutate(&corpus->entries[generated->parent], candidate,
			       &generated->size, rng, hopper->enabled);
	}
}

static int hopper_observe_seed(struct hopper_module *hopper,
			      TEEC_Context *context, const char *run_dir,
			      const uint8_t *candidate, size_t size,
			      size_t parent, const struct feedback *feedback,
			      struct corpus *corpus, uint64_t *artifact_id)
{
	uint8_t targets[CORE_FUZZ_TA_MAX_OPS];
	size_t count = 0;

	if (!hopper->enabled)
		return 0;
	count = collect_targets(candidate, size, targets);
	for (size_t i = 0; i < count; i++) {
		int status = learn_target(context, run_dir, candidate, size,
			targets[i], 0, parent, feedback, corpus,
			&hopper->learned, artifact_id);

		if (status)
			return status;
	}
	return 0;
}

static int hopper_observe_candidate(struct hopper_module *hopper,
				   TEEC_Context *context,
				   const char *run_dir,
				   const uint8_t *candidate,
				   const struct generated_case *generated,
				   uint64_t iteration,
				   const struct feedback *feedback,
				   struct corpus *corpus,
				   uint64_t *artifact_id,
				   struct rng *rng)
{
	uint8_t targets[CORE_FUZZ_TA_MAX_OPS];
	size_t count = 0;
	size_t before = 0;
	int status = 0;

	if (!hopper->enabled)
		return 0;
	count = collect_targets(candidate, generated->size, targets);
	if (!count)
		return 0;
	before = hopper->target_coverage.total;
	status = learn_target(context, run_dir, candidate,
		generated->size,
		generated->assembled ? generated->assembled_target :
		targets[random_below(rng, count)], iteration,
		generated->parent, feedback, corpus, &hopper->learned,
		artifact_id);
	if (generated->assembled) {
		if (status == PROBE_CRASH)
			hopper->assembly_crashes++;
		if (!status)
			hopper->assembly_target_new_edges +=
				hopper->target_coverage.total - before;
	}
	return status;
}

static bool parse_u64(const char *text, uint64_t *number)
{
	char *end = NULL;
	unsigned long long value = 0;

	errno = 0;
	value = strtoull(text, &end, 0);
	if (errno || !end || *end || end == text || text[0] == '-')
		return false;
	*number = value;
	return true;
}

static bool parse_hopper_mode(const char *text, bool *enabled)
{
	if (!strcmp(text, "--hopper=on")) {
		*enabled = true;
		return true;
	}
	if (!strcmp(text, "--hopper=off")) {
		*enabled = false;
		return true;
	}
	return false;
}

static bool monotonic_elapsed(const struct timespec *started,
			      uint64_t *seconds)
{
	struct timespec now = { 0 };

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return false;
	if (now.tv_sec < started->tv_sec) {
		*seconds = 0;
		return true;
	}
	*seconds = (uint64_t)(now.tv_sec - started->tv_sec);
	if (now.tv_nsec < started->tv_nsec && *seconds)
		(*seconds)--;
	return true;
}

int main(int argc, char *argv[])
{
	uint8_t candidate[CORE_FUZZ_TA_MAX_INPUT + 1];
	struct corpus corpus = { 0 };
	struct rng rng = { .state = 1 };
	struct feedback feedback = { 0 };
	struct coverage_state coverage = { 0 };
	struct hopper_module hopper = { .enabled = true };
	struct feedback_criterion edge_criterion = {
		.name = "core-edge-v1",
		.state = &coverage,
		.new_features = coverage_new,
		.commit = coverage_commit,
	};
	struct feedback_criterion target_criterion = {
		.name = "target-core-edge-v1",
		.state = &hopper.target_coverage,
		.new_features = target_coverage_new,
		.commit = target_coverage_commit,
	};
	struct dirent **seeds = NULL;
	TEEC_Context context = { 0 };
	TEEC_Result result = TEEC_SUCCESS;
	char run_dir[PATH_CAP] = { 0 };
	char path[PATH_CAP];
	uint64_t iterations = 0;
	uint64_t artifact_id = 0;
	uint64_t kept = 0;
	uint64_t duration_seconds = 0;
	uint64_t elapsed_seconds = 0;
	uint64_t last_progress_seconds = 0;
	struct timespec started = { 0 };
	bool seen_seed = false;
	bool seen_mode = false;
	bool seen_duration = false;
	bool duration_reached = false;
	bool valid_args = true;
	int seed_count = 0;
	int exit_status = 0;

	if (argc < 4 || argc > 7 || !parse_u64(argv[3], &iterations) ||
	    !iterations || iterations > UINT64_C(100000000))
		valid_args = false;
	for (int i = 4; valid_args && i < argc; i++) {
		if (!strncmp(argv[i], "--hopper=", 9)) {
			if (seen_mode ||
			    !parse_hopper_mode(argv[i], &hopper.enabled))
				valid_args = false;
			seen_mode = true;
		} else if (!strncmp(argv[i], "--duration-seconds=", 19)) {
			if (seen_duration ||
			    !parse_u64(argv[i] + 19, &duration_seconds) ||
			    !duration_seconds || duration_seconds > 86400)
				valid_args = false;
			seen_duration = true;
		} else if (!seen_seed && parse_u64(argv[i], &rng.state)) {
			seen_seed = true;
		} else {
			valid_args = false;
		}
	}
	if (!valid_args) {
		fprintf(stderr, "usage: %s SEED_DIR OUTPUT_DIR ITERATIONS "
			"[RNG_SEED] [--hopper=on|off] "
			"[--duration-seconds=1..86400]\n", argv[0]);
		return 2;
	}
	if (!rng.state)
		rng.state = 1;
	seed_count = scandir(argv[1], &seeds, seed_filter, alphasort);
	if (seed_count <= 0) {
		fprintf(stderr, "no .bin seeds in %s\n", argv[1]);
		return 2;
	}
	if (!feedback_register(&feedback, &edge_criterion) ||
	    (hopper.enabled &&
	     !feedback_register(&feedback, &target_criterion)) ||
	    !create_run_dir(argv[2], run_dir, sizeof(run_dir),
			    hopper.enabled)) {
		fprintf(stderr, "cannot prepare feedback or output directory\n");
		exit_status = 2;
		goto out;
	}
	printf("FUZZ_RUN_DIR=%s\nFUZZ_RNG_SEED=%" PRIu64
	       "\nFUZZ_HOPPER=%s\n", run_dir, rng.state,
	       hopper.enabled ? "on" : "off");
	fflush(stdout);
	result = TEEC_InitializeContext(NULL, &context);
	if (result != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_InitializeContext: 0x%08" PRIx32 "\n",
			(uint32_t)result);
		exit_status = 2;
		goto out;
	}
	for (int i = 0; i < seed_count; i++) {
		struct execution first = { 0 };
		struct execution second = { 0 };
		size_t size = 0;
		size_t seed_parent = 0;

		if ((size_t)snprintf(path, sizeof(path), "%s/%s", argv[1],
			     seeds[i]->d_name) >= sizeof(path) ||
		    !read_seed(path, candidate, &size) ||
		    !corpus_add(&corpus, candidate, size)) {
			fprintf(stderr, "cannot load seed %s\n", seeds[i]->d_name);
			exit_status = 2;
			goto finalize;
		}
		seed_parent = corpus.count - 1;
		if (!execute_recorded(&context, run_dir, candidate, size,
				      -1, 0, &first)) {
			fprintf(stderr, "cannot save current seed input\n");
			exit_status = 2;
			goto finalize;
		}
		if (is_target_dead(&first)) {
			if (!save_artifact(run_dir, "crashes", artifact_id++,
					   candidate, size, 0, seed_parent,
					   &first, 0))
				fprintf(stderr, "cannot save crash input\n");
			exit_status = 3;
			goto finalize;
		}
		if (!first.session_opened) {
			fprintf(stderr, "TEEC_OpenSession failed: 0x%08" PRIx32
				"\n", (uint32_t)first.result);
			exit_status = 2;
			goto finalize;
		}
		if (!execute_recorded(&context, run_dir, candidate, size,
				      -1, 0, &second)) {
			fprintf(stderr, "cannot save current seed replay\n");
			exit_status = 2;
			goto finalize;
		}
		if (is_target_dead(&second)) {
			if (!save_artifact(run_dir, "crashes", artifact_id++,
					   candidate, size, 0, seed_parent,
					   &second, 0))
				fprintf(stderr, "cannot save crash input\n");
			exit_status = 3;
			goto finalize;
		}
		if (!second.session_opened) {
			fprintf(stderr, "TEEC_OpenSession failed during seed replay: "
				"0x%08" PRIx32 "\n", (uint32_t)second.result);
			exit_status = 2;
			goto finalize;
		}
		feedback_commit(&feedback, &first, &second);
		printf("SEED=%s RESULT=0x%08" PRIx32 " EDGES=%zu\n",
		       seeds[i]->d_name, (uint32_t)first.result,
		       coverage.total);
		exit_status = hopper_observe_seed(&hopper, &context, run_dir,
			candidate, size, seed_parent, &feedback, &corpus,
			&artifact_id);
		if (exit_status)
			goto finalize;
	}
	if (!coverage.total) {
		fprintf(stderr, "no stable core coverage from seeds\n");
		exit_status = 2;
		goto finalize;
	}
	printf("FUZZ_BASELINE_SEEDS=%d CORPUS=%zu EDGES=%zu\n",
	       seed_count, corpus.count, coverage.total);
	fflush(stdout);
	/* The campaign duration excludes seed validation and HOPPER baseline. */
	if (clock_gettime(CLOCK_MONOTONIC, &started)) {
		perror("clock_gettime");
		exit_status = 2;
		goto finalize;
	}
	for (uint64_t iteration = 1; iteration <= iterations; iteration++) {
		struct execution first = { 0 };
		struct execution second = { 0 };
		struct generated_case generated = { 0 };
		size_t new_features = 0;

		if (!monotonic_elapsed(&started, &elapsed_seconds)) {
			perror("clock_gettime");
			exit_status = 2;
			break;
		}
		if (duration_seconds && elapsed_seconds >= duration_seconds) {
			duration_reached = true;
			break;
		}
		generate_case(&hopper, &corpus, &rng, candidate, &generated,
			      iteration);
		if (!execute_recorded(&context, run_dir, candidate,
				      generated.size,
				      -1, 0, &first)) {
			fprintf(stderr, "cannot save current input at iteration %"
				PRIu64 "\n", iteration);
			exit_status = 2;
			break;
		}
		if (generated.assembled &&
		    hopper.assembly_samples < MAX_ASSEMBLY_SAMPLES) {
			if (!save_assembly_sample(run_dir, iteration,
						  generated.parent,
						  generated.template_index,
						  generated.assembled_target,
						  candidate,
						  generated.size, &first)) {
				fprintf(stderr, "cannot save assembly sample\n");
				exit_status = 2;
				break;
			}
			hopper.assembly_samples++;
		}
		if (is_target_dead(&first)) {
			if (generated.assembled)
				hopper.assembly_crashes++;
			if (!save_artifact(run_dir, "crashes", artifact_id++,
					   candidate, generated.size, iteration,
					   generated.parent,
					   &first, 0))
				fprintf(stderr, "cannot save crash input\n");
			printf("FUZZ_CRASH ITER=%" PRIu64 " RESULT=0x%08"
			       PRIx32 "\n", iteration, (uint32_t)first.result);
			exit_status = 3;
			break;
		}
		if (!first.session_opened) {
			fprintf(stderr, "TEEC_OpenSession failed at iteration %"
				PRIu64 ": 0x%08" PRIx32 "\n", iteration,
				(uint32_t)first.result);
			exit_status = 2;
			break;
		}
		if (generated.assembled) {
			uint32_t step_status = 0;

			if (output_step_status(&first,
					       generated.assembled_target,
					       generated.assembled_opcode,
					       &step_status)) {
				hopper.assembly_target_records++;
				if (step_status == TEEC_SUCCESS)
					hopper.assembly_target_success++;
			}
		}
		if (feedback_new(&feedback, &first, &first)) {
			if (!execute_recorded(&context, run_dir, candidate,
					      generated.size,
					      -1, 0, &second)) {
				fprintf(stderr, "cannot save current replay at iteration %"
					PRIu64 "\n", iteration);
				exit_status = 2;
				break;
			}
			if (is_target_dead(&second)) {
				if (generated.assembled)
					hopper.assembly_crashes++;
				if (!save_artifact(run_dir, "crashes", artifact_id++,
						   candidate, generated.size,
						   iteration, generated.parent,
						   &second, 0))
					fprintf(stderr, "cannot save crash input\n");
				printf("FUZZ_CRASH ITER=%" PRIu64 " RESULT=0x%08"
				       PRIx32 "\n", iteration,
				       (uint32_t)second.result);
				exit_status = 3;
				break;
			}
			if (!second.session_opened) {
				fprintf(stderr, "TEEC_OpenSession failed during replay at "
					"iteration %" PRIu64 ": 0x%08" PRIx32
					"\n", iteration, (uint32_t)second.result);
				exit_status = 2;
				break;
			}
			new_features = feedback_new(&feedback, &first, &second);
			if (new_features) {
				if (generated.assembled)
					hopper.assembly_new_edges += new_features;
				if (!save_artifact(run_dir, "corpus", artifact_id++,
						   candidate, generated.size,
						   iteration, generated.parent,
						   &first, new_features)) {
					fprintf(stderr, "cannot save novel input\n");
					exit_status = 2;
					break;
				}
				feedback_commit(&feedback, &first, &second);
				if (!corpus_add(&corpus, candidate,
						generated.size) &&
				    corpus.count != MAX_CORPUS_ENTRIES) {
					fprintf(stderr, "cannot add novel input to corpus\n");
					exit_status = 2;
					break;
				}
				kept++;
				printf("FUZZ_NEW ITER=%" PRIu64 " NEW=%zu EDGES=%zu "
				       "CORPUS=%zu\n", iteration, new_features,
				       coverage.total, corpus.count);
				fflush(stdout);
			}
		}
		exit_status = hopper_observe_candidate(&hopper, &context,
			run_dir, candidate, &generated, iteration, &feedback,
			&corpus, &artifact_id, &rng);
		if (exit_status)
			break;
		if (!monotonic_elapsed(&started, &elapsed_seconds)) {
			perror("clock_gettime");
			exit_status = 2;
			break;
		}
		if (iteration % 100 == 0 || iteration == iterations ||
		    elapsed_seconds >= last_progress_seconds + 300) {
			printf("FUZZ_PROGRESS ITER=%" PRIu64 " EDGES=%zu "
			       "TARGET_EDGES=%zu LEARNED=%zu KEPT=%" PRIu64
			       " CORPUS=%zu ASSEMBLED=%zu ASSEMBLY_NEW=%zu "
			       "ELAPSED_SEC=%" PRIu64 "\n",
			       iteration, coverage.total,
			       hopper.target_coverage.total,
			       hopper.learned.count, kept, corpus.count,
			       hopper.assemblies, hopper.assembly_new_edges,
			       elapsed_seconds);
			last_progress_seconds = elapsed_seconds;
			fflush(stdout);
		}
	}
	if (!monotonic_elapsed(&started, &elapsed_seconds))
		perror("clock_gettime");
	printf("FUZZ_DONE STATUS=%d HOPPER=%s EDGES=%zu TARGET_EDGES=%zu "
	       "LEARNED=%zu RELATIONS=%zu KEPT=%" PRIu64
	       " CORPUS=%zu ASSEMBLY_TEMPLATES=%zu "
	       "ASSEMBLY_ATTEMPTS=%zu ASSEMBLED=%zu "
	       "ASSEMBLY_SAMPLES=%zu ASSEMBLY_RECORDS=%zu "
	       "ASSEMBLY_TARGET_OK=%zu "
	       "ASSEMBLY_NEW=%zu ASSEMBLY_TARGET_NEW=%zu "
	       "ASSEMBLY_CRASHES=%zu TA_INVOKES=%" PRIu64
	       " DURATION_SEC=%" PRIu64 " ELAPSED_SEC=%" PRIu64
	       " STOP_REASON=%s RUN_DIR=%s\n",
	       exit_status, hopper.enabled ? "on" : "off", coverage.total,
	       hopper.target_coverage.total, hopper.learned.count,
	       hopper.learned.relations, kept, corpus.count,
	       hopper.learned.assemblable, hopper.assembly_attempts,
	       hopper.assemblies, hopper.assembly_samples,
	       hopper.assembly_target_records,
	       hopper.assembly_target_success, hopper.assembly_new_edges,
	       hopper.assembly_target_new_edges,
	       hopper.assembly_crashes, ta_invocations,
	       duration_seconds, elapsed_seconds,
	       exit_status ? "error" : duration_reached ? "duration" : "iterations",
	       run_dir);
	for (uint8_t opcode = CORE_FUZZ_TA_ALLOC;
	     opcode <= CORE_FUZZ_TA_ASYMM_VERIFY; opcode++)
		printf("FUZZ_OPCODE opcode=%u calls=%" PRIu64
		       " success=%" PRIu64 "\n", opcode,
		       opcode_calls[opcode], opcode_success[opcode]);
	fflush(stdout);
finalize:
	TEEC_FinalizeContext(&context);
out:
	for (int i = 0; i < seed_count; i++)
		free(seeds[i]);
	free(seeds);
	corpus_free(&corpus);
	return exit_status;
}
