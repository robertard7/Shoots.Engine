#include "engine_internal.h"

#include <string.h>
#ifndef NDEBUG
#include <assert.h>
#endif

struct shoots_provider_runtime {
  uint32_t state;
  uint8_t config_allow_background_threads;
  uint8_t config_allow_filesystem_io;
  uint8_t config_allow_network_io;
  uint8_t effective_allow_background_threads;
  uint8_t effective_allow_filesystem_io;
  uint8_t effective_allow_network_io;
};

enum shoots_provider_runtime_state {
  SHOOTS_PROVIDER_RUNTIME_STATE_UNINITIALIZED = 0,
  SHOOTS_PROVIDER_RUNTIME_STATE_READY = 1,
  SHOOTS_PROVIDER_RUNTIME_STATE_DESTROYED = 2
};

#ifndef NDEBUG
static void shoots_provider_runtime_assert_invariants(
  const shoots_provider_runtime_t *runtime) {
  if (runtime == NULL) {
    return;
  }
  if (runtime->state == SHOOTS_PROVIDER_RUNTIME_STATE_READY ||
      runtime->state == SHOOTS_PROVIDER_RUNTIME_STATE_DESTROYED) {
    assert(runtime->effective_allow_background_threads == 0);
    assert(runtime->effective_allow_filesystem_io == 0);
    assert(runtime->effective_allow_network_io == 0);
  }
}
#endif

static void shoots_error_clear(shoots_error_info_t *out_error) {
  if (out_error == NULL) {
    return;
  }
  out_error->code = SHOOTS_OK;
  out_error->severity = SHOOTS_SEVERITY_RECOVERABLE;
  out_error->message = NULL;
}

static void shoots_error_set(shoots_error_info_t *out_error,
                             shoots_error_code_t code,
                             shoots_error_severity_t severity,
                             const char *message) {
  if (out_error == NULL) {
    return;
  }
  out_error->code = code;
  out_error->severity = severity;
  out_error->message = message;
}

shoots_error_code_t shoots_provider_runtime_create(
  shoots_engine_t *engine,
  const shoots_config_t *config,
  shoots_provider_runtime_t **out_runtime,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_runtime == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "out_runtime is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_runtime = NULL;
  if (engine == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (config == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "config is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }

  shoots_provider_runtime_t *runtime =
      (shoots_provider_runtime_t *)shoots_engine_alloc_internal(
          engine, sizeof(*runtime), out_error);
  if (runtime == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memset(runtime, 0, sizeof(*runtime));
  runtime->state = SHOOTS_PROVIDER_RUNTIME_STATE_READY;
  runtime->config_allow_background_threads = config->allow_background_threads;
  runtime->config_allow_filesystem_io = config->allow_filesystem_io;
  runtime->config_allow_network_io = config->allow_network_io;
  runtime->effective_allow_background_threads = 0;
  runtime->effective_allow_filesystem_io = 0;
  runtime->effective_allow_network_io = 0;
#ifndef NDEBUG
  shoots_provider_runtime_assert_invariants(runtime);
#endif

  *out_runtime = runtime;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_provider_runtime_destroy(
  shoots_engine_t *engine,
  shoots_provider_runtime_t *runtime,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (engine == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (runtime == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "runtime is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (engine->provider_runtime != runtime) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "runtime not attached");
    return SHOOTS_ERR_INVALID_STATE;
  }
#ifndef NDEBUG
  shoots_provider_runtime_assert_invariants(runtime);
#endif
  if (runtime->state != SHOOTS_PROVIDER_RUNTIME_STATE_READY) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "runtime state invalid");
    return SHOOTS_ERR_INVALID_STATE;
  }
  runtime->state = SHOOTS_PROVIDER_RUNTIME_STATE_DESTROYED;
  engine->provider_runtime = NULL;
  shoots_engine_alloc_free_internal(engine, runtime);
  return SHOOTS_OK;
}

shoots_error_code_t shoots_provider_runtime_validate_ready(
  const shoots_provider_runtime_t *runtime,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (runtime == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "runtime is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (runtime->state != SHOOTS_PROVIDER_RUNTIME_STATE_READY) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "runtime state invalid");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (runtime->effective_allow_background_threads != 0 ||
      runtime->effective_allow_filesystem_io != 0 ||
      runtime->effective_allow_network_io != 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "runtime effective permissions invalid");
    return SHOOTS_ERR_INVALID_STATE;
  }
#ifndef NDEBUG
  shoots_provider_runtime_assert_invariants(runtime);
#endif
  return SHOOTS_OK;
}

shoots_error_code_t shoots_provider_descriptor_validate(
  const shoots_provider_descriptor_t *descriptor,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (descriptor == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "descriptor is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (descriptor->provider_id_len == 0 ||
      descriptor->provider_id_len >= SHOOTS_PROVIDER_ID_MAX) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider_id length invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (descriptor->provider_id[descriptor->provider_id_len] != '\0') {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider_id not terminated");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  for (uint8_t index = 0; index < descriptor->provider_id_len; index++) {
    if (descriptor->provider_id[index] == '\0') {
      shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                       "provider_id contains null");
      return SHOOTS_ERR_INVALID_ARGUMENT;
    }
  }
  if (descriptor->supported_tool_categories == 0 ||
      (descriptor->supported_tool_categories & ~SHOOTS_PROVIDER_TOOL_CATEGORY_MASK) != 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider categories invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (descriptor->max_concurrency == 0 ||
      descriptor->max_concurrency > SHOOTS_PROVIDER_MAX_CONCURRENCY) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider concurrency invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if ((descriptor->guarantees_mask & ~SHOOTS_PROVIDER_GUARANTEE_MASK) != 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider guarantees invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  return SHOOTS_OK;
}
