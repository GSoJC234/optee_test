// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Jaehun Lee
 */

#include <core_fuzz_ta.h>
#include <fuzz_run.h>
#include <tee_internal_api.h>
#include <stddef.h>
#include <stdint.h>

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
	return fuzz_run(param_types, params);
}
