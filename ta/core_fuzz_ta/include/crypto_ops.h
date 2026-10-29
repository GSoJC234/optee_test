/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Jaehun Lee
 */
#ifndef CRYPTO_OPS_H
#define CRYPTO_OPS_H

#include <fuzz_context.h>
#include <fuzz_op.h>
#include <tee_internal_api.h>
#include <stdint.h>

TEE_Result crypto_execute(struct fuzz_context *ctx,
			  const struct fuzz_op *op, uint8_t *record);
void crypto_cleanup(struct fuzz_context *ctx);

#endif /* CRYPTO_OPS_H */
