/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Jaehun Lee
 */
#ifndef FUZZ_RUN_H
#define FUZZ_RUN_H

#include <tee_internal_api.h>
#include <stdint.h>

TEE_Result fuzz_run(uint32_t param_types, TEE_Param params[4]);

#endif /* FUZZ_RUN_H */
