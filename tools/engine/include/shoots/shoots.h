#ifndef SHOOTS_ENGINE_SHOOTS_H
#define SHOOTS_ENGINE_SHOOTS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct shoots_engine shoots_engine_t;
typedef struct shoots_model shoots_model_t;


#define SHOOTS_ENGINE_ABI_VERSION_MAJOR 1u
#define SHOOTS_ENGINE_ABI_VERSION_MINOR 0u
#define SHOOTS_ENGINE_ABI_VERSION_PATCH 0u
#define SHOOTS_ENGINE_ABI_VERSION ((SHOOTS_ENGINE_ABI_VERSION_MAJOR * 10000u) + \
                                   (SHOOTS_ENGINE_ABI_VERSION_MINOR * 100u) + \
                                   SHOOTS_ENGINE_ABI_VERSION_PATCH)

typedef enum shoots_error_code {
  SHOOTS_OK = 0,
  SHOOTS_ERR_INVALID_ARGUMENT = 1,
  SHOOTS_ERR_INVALID_STATE = 2,
  SHOOTS_ERR_OUT_OF_MEMORY = 3,
  SHOOTS_ERR_RESOURCE_UNAVAILABLE = 4,
  SHOOTS_ERR_UNSUPPORTED = 5,
  SHOOTS_ERR_INTERNAL_FAILURE = 6
} shoots_error_code_t;

typedef enum shoots_error_severity {
  SHOOTS_SEVERITY_RECOVERABLE = 0,
  SHOOTS_SEVERITY_FATAL = 1
} shoots_error_severity_t;

typedef struct shoots_error_info {
  shoots_error_code_t code;
  shoots_error_severity_t severity;
  const char *message;
} shoots_error_info_t;

typedef struct shoots_config {
  const char *model_root_path;
  size_t max_memory_bytes;
  uint64_t max_execution_steps;
  uint8_t allow_background_threads;
  uint8_t allow_filesystem_io;
  uint8_t allow_network_io;
} shoots_config_t;

typedef struct shoots_inference_request {
  shoots_model_t *model;
  const uint32_t *input_tokens;
  size_t input_token_count;
  uint32_t max_output_tokens;
  uint64_t max_execution_steps;
} shoots_inference_request_t;

typedef struct shoots_inference_response {
  uint32_t *output_tokens;
  size_t output_token_count;
  uint32_t stop_reason;
  uint32_t input_token_count;
} shoots_inference_response_t;

typedef struct shoots_embedding_request {
  shoots_model_t *model;
  const uint32_t *input_tokens;
  size_t input_token_count;
  uint64_t max_execution_steps;
} shoots_embedding_request_t;

typedef struct shoots_embedding_response {
  float *embedding;
  size_t embedding_length;
  uint32_t input_token_count;
} shoots_embedding_response_t;

shoots_error_code_t shoots_engine_create(
  const shoots_config_t *config,
  shoots_engine_t **out_engine,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_engine_destroy(
  shoots_engine_t *engine,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_engine_free(
  shoots_engine_t *engine,
  void *buffer,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_model_load(
  shoots_engine_t *engine,
  const char *model_identifier,
  shoots_model_t **out_model,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_model_unload(
  shoots_engine_t *engine,
  shoots_model_t *model,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_infer(
  shoots_engine_t *engine,
  const shoots_inference_request_t *request,
  shoots_inference_response_t *response,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_embed(
  shoots_engine_t *engine,
  const shoots_embedding_request_t *request,
  shoots_embedding_response_t *response,
  shoots_error_info_t *out_error);

#ifdef __cplusplus
}
#endif

#endif
