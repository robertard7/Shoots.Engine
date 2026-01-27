#include "provider_runtime.h"

#include <string.h>

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
  return SHOOTS_OK;
}
