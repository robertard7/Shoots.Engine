#ifndef SHOOTS_PROVIDER_RUNTIME_H
#define SHOOTS_PROVIDER_RUNTIME_H

#include "shoots/shoots.h"

#include <stdint.h>

typedef struct shoots_provider_runtime shoots_provider_runtime_t;

#define SHOOTS_PROVIDER_TOOL_ID_MAX 64u
#define SHOOTS_PROVIDER_ARG_MAX_BYTES 4096u
#define SHOOTS_PROVIDER_OUTPUT_MAX_BYTES 4096u
#define SHOOTS_PROVIDER_ID_MAX 64u
#define SHOOTS_PROVIDER_MAX_CONCURRENCY 1024u

#define SHOOTS_PROVIDER_TOOL_CATEGORY_EXECUTION (1u << 0)
#define SHOOTS_PROVIDER_TOOL_CATEGORY_INTEGRATION (1u << 1)
#define SHOOTS_PROVIDER_TOOL_CATEGORY_MASK (SHOOTS_PROVIDER_TOOL_CATEGORY_EXECUTION | \
                                            SHOOTS_PROVIDER_TOOL_CATEGORY_INTEGRATION)

#define SHOOTS_PROVIDER_GUARANTEE_DETERMINISTIC (1u << 0)
#define SHOOTS_PROVIDER_GUARANTEE_IDEMPOTENT (1u << 1)
#define SHOOTS_PROVIDER_GUARANTEE_PURE (1u << 2)
#define SHOOTS_PROVIDER_GUARANTEE_MASK (SHOOTS_PROVIDER_GUARANTEE_DETERMINISTIC | \
                                        SHOOTS_PROVIDER_GUARANTEE_IDEMPOTENT | \
                                        SHOOTS_PROVIDER_GUARANTEE_PURE)

typedef enum shoots_provider_result_code {
  SHOOTS_PROVIDER_RESULT_SUCCESS = 0,
  SHOOTS_PROVIDER_RESULT_FAILURE = 1,
  SHOOTS_PROVIDER_RESULT_REJECTED = 2
} shoots_provider_result_code_t;

typedef struct shoots_provider_request {
  uint64_t session_id;
  uint64_t plan_id;
  uint64_t execution_slot;
  uint64_t request_id;
  uint8_t provider_id_len;
  char provider_id[SHOOTS_PROVIDER_ID_MAX];
  uint8_t tool_id_len;
  char tool_id[SHOOTS_PROVIDER_TOOL_ID_MAX];
  uint32_t tool_version;
  uint64_t capability_mask;
  uint64_t input_hash;
  uint32_t arg_size;
  uint8_t arg_blob[SHOOTS_PROVIDER_ARG_MAX_BYTES];
} shoots_provider_request_t;

typedef struct shoots_provider_receipt {
  uint64_t session_id;
  uint64_t plan_id;
  uint64_t execution_slot;
  uint64_t request_id;
  uint8_t provider_id_len;
  char provider_id[SHOOTS_PROVIDER_ID_MAX];
  uint8_t tool_id_len;
  char tool_id[SHOOTS_PROVIDER_TOOL_ID_MAX];
  uint32_t tool_version;
  uint64_t input_hash;
  shoots_provider_result_code_t result_code;
  uint32_t output_size;
  uint8_t output_blob[SHOOTS_PROVIDER_OUTPUT_MAX_BYTES];
} shoots_provider_receipt_t;

typedef struct shoots_provider_descriptor {
  uint8_t provider_id_len;
  char provider_id[SHOOTS_PROVIDER_ID_MAX];
  uint32_t supported_tool_categories;
  uint32_t max_concurrency;
  uint32_t guarantees_mask;
} shoots_provider_descriptor_t;

shoots_error_code_t shoots_provider_descriptor_validate(
  const shoots_provider_descriptor_t *descriptor,
  shoots_error_info_t *out_error);

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
