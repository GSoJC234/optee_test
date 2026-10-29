/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Jaehun Lee
 */
#ifndef FUZZ_OP_H
#define FUZZ_OP_H

#include <stdint.h>

struct fuzz_op {
	uint8_t opcode;
	uint8_t slot;
	uint8_t selector;
	uint16_t data_len;
	uint16_t aux;
	const uint8_t *data;
};

#endif /* FUZZ_OP_H */
