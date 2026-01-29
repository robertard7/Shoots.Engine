#ifndef SHOOTS_PROVIDER_RUNTIME_H
#define SHOOTS_PROVIDER_RUNTIME_H

#include "shoots/shoots.h"

#include <stdint.h>

typedef struct shoots_provider_runtime shoots_provider_runtime_t;

#define SHOOTS_PROVIDER_TOOL_ID_MAX 64u
#define SHOOTS_PROVIDER_ARG_MAX_BYTES 4096u
#define SHOOTS_PROVIDER_OUTPUT_MAX_BYTES 4096u

typedef enum shoots_provider_result_code {
  SHOOTS_PROVIDER_RESULT_SUCCESS = 0,
  SHOOTS_PROVIDER_RESULT_FAILURE = 1,
  SHOOTS_PROVIDER_RESULT_REJECTED = 2
} shoots_provider_result_code_t;

typedef struct shoots_provider_request {
  uint64_t session_id;
  uint64_t plan_id;
  uint64_t execution_slot;
  uint8_t tool_id_len;
  char tool_id[SHOOTS_PROVIDER_TOOL_ID_MAX];
  uint32_t tool_version;
  uint64_t input_hash;
  uint32_t arg_size;
  uint8_t arg_blob[SHOOTS_PROVIDER_ARG_MAX_BYTES];
} shoots_provider_request_t;

typedef struct shoots_provider_receipt {
  uint64_t session_id;
  uint64_t plan_id;
  uint64_t execution_slot;
  uint8_t tool_id_len;
  char tool_id[SHOOTS_PROVIDER_TOOL_ID_MAX];
  uint32_t tool_version;
  uint64_t input_hash;
  shoots_provider_result_code_t result_code;
  uint32_t output_size;
  uint8_t output_blob[SHOOTS_PROVIDER_OUTPUT_MAX_BYTES];
} shoots_provider_receipt_t;

shoots_error_code_t shoots_provider_runtime_create(
  shoots_engine_t *engine,
  const shoots_config_t *config,
  shoots_provider_runtime_t **out_runtime,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_provider_runtime_destroy(
  shoots_engine_t *engine,
  shoots_provider_runtime_t *runtime,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_provider_runtime_validate_ready(
  const shoots_provider_runtime_t *runtime,
  shoots_error_info_t *out_error);

#endif
