#include "engine_internal.h"

#include <stdio.h>
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

static void shoots_provider_format_id(const shoots_provider_descriptor_t *descriptor,
                                      char *buffer,
                                      size_t buffer_len) {
  if (buffer == NULL || buffer_len == 0) {
    return;
  }
  if (descriptor == NULL) {
    strncpy(buffer, "(null)", buffer_len);
    buffer[buffer_len - 1] = '\0';
    return;
  }
  size_t length = 0;
  for (; length + 1 < buffer_len && length < SHOOTS_PROVIDER_ID_MAX; length++) {
    char value = descriptor->provider_id[length];
    if (value == '\0') {
      break;
    }
    buffer[length] = value;
  }
  buffer[length] = '\0';
  if (length == 0) {
    strncpy(buffer, "(empty)", buffer_len);
    buffer[buffer_len - 1] = '\0';
  }
}

static void shoots_provider_format_id_value(const char *provider_id,
                                            char *buffer,
                                            size_t buffer_len) {
  if (buffer == NULL || buffer_len == 0) {
    return;
  }
  if (provider_id == NULL) {
    strncpy(buffer, "(null)", buffer_len);
    buffer[buffer_len - 1] = '\0';
    return;
  }
  size_t length = 0;
  for (; length + 1 < buffer_len && length < SHOOTS_PROVIDER_ID_MAX; length++) {
    char value = provider_id[length];
    if (value == '\0') {
      break;
    }
    buffer[length] = value;
  }
  buffer[length] = '\0';
  if (length == 0) {
    strncpy(buffer, "(empty)", buffer_len);
    buffer[buffer_len - 1] = '\0';
  }
}

static shoots_error_code_t shoots_provider_emit_register_entry(
  shoots_engine_t *engine,
  const char *provider_id,
  const char *status,
  const char *reason,
  shoots_error_info_t *out_error) {
  const char *safe_provider_id = provider_id != NULL ? provider_id : "(null)";
  const char *safe_status = status != NULL ? status : "UNKNOWN";
  const char *safe_reason = reason != NULL ? reason : "";
  const char *reason_format = reason != NULL && reason[0] != '\0'
                                  ? " reason=%s"
                                  : "%s";
  int required = snprintf(NULL, 0,
                          "provider_register provider_id=%s status=%s",
                          safe_provider_id, safe_status);
  if (required < 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger format failed");
    return SHOOTS_ERR_INVALID_STATE;
  }
  int reason_required = snprintf(NULL, 0, reason_format, safe_reason);
  if (reason_required < 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger format failed");
    return SHOOTS_ERR_INVALID_STATE;
  }
  size_t payload_len = (size_t)required + (size_t)reason_required;
  if (payload_len > SHOOTS_LEDGER_MAX_BYTES) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger payload too large");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  char *payload = (char *)shoots_engine_alloc_internal(
      engine, payload_len + 1, out_error);
  if (payload == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  int written = snprintf(payload, payload_len + 1,
                         "provider_register provider_id=%s status=%s",
                         safe_provider_id, safe_status);
  if (written < 0) {
    shoots_engine_alloc_free_internal(engine, payload);
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger format failed");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (reason_required > 0 && reason != NULL && reason[0] != '\0') {
    int reason_written = snprintf(payload + written,
                                  payload_len + 1 - (size_t)written,
                                  " reason=%s",
                                  safe_reason);
    if (reason_written < 0) {
      shoots_engine_alloc_free_internal(engine, payload);
      shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                       "ledger format failed");
      return SHOOTS_ERR_INVALID_STATE;
    }
  }
  shoots_ledger_entry_t *entry = NULL;
  shoots_error_code_t status_code = shoots_ledger_append_internal(
      engine, SHOOTS_LEDGER_ENTRY_DECISION, payload, &entry, out_error);
  shoots_engine_alloc_free_internal(engine, payload);
  return status_code;
}

static shoots_error_code_t shoots_provider_emit_unregister_entry(
  shoots_engine_t *engine,
  const char *provider_id,
  const char *status,
  const char *reason,
  shoots_error_info_t *out_error) {
  const char *safe_provider_id = provider_id != NULL ? provider_id : "(null)";
  const char *safe_status = status != NULL ? status : "UNKNOWN";
  const char *safe_reason = reason != NULL ? reason : "";
  const char *reason_format = reason != NULL && reason[0] != '\0'
                                  ? " reason=%s"
                                  : "%s";
  int required = snprintf(NULL, 0,
                          "provider_unregister provider_id=%s status=%s",
                          safe_provider_id, safe_status);
  if (required < 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger format failed");
    return SHOOTS_ERR_INVALID_STATE;
  }
  int reason_required = snprintf(NULL, 0, reason_format, safe_reason);
  if (reason_required < 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger format failed");
    return SHOOTS_ERR_INVALID_STATE;
  }
  size_t payload_len = (size_t)required + (size_t)reason_required;
  if (payload_len > SHOOTS_LEDGER_MAX_BYTES) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger payload too large");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  char *payload = (char *)shoots_engine_alloc_internal(
      engine, payload_len + 1, out_error);
  if (payload == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  int written = snprintf(payload, payload_len + 1,
                         "provider_unregister provider_id=%s status=%s",
                         safe_provider_id, safe_status);
  if (written < 0) {
    shoots_engine_alloc_free_internal(engine, payload);
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger format failed");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (reason_required > 0 && reason != NULL && reason[0] != '\0') {
    int reason_written = snprintf(payload + written,
                                  payload_len + 1 - (size_t)written,
                                  " reason=%s",
                                  safe_reason);
    if (reason_written < 0) {
      shoots_engine_alloc_free_internal(engine, payload);
      shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                       "ledger format failed");
      return SHOOTS_ERR_INVALID_STATE;
    }
  }
  shoots_ledger_entry_t *entry = NULL;
  shoots_error_code_t status_code = shoots_ledger_append_internal(
      engine, SHOOTS_LEDGER_ENTRY_DECISION, payload, &entry, out_error);
  shoots_engine_alloc_free_internal(engine, payload);
  return status_code;
}

static shoots_error_code_t shoots_provider_emit_lock_entry(
  shoots_engine_t *engine,
  const char *status,
  shoots_error_info_t *out_error) {
  const char *safe_status = status != NULL ? status : "UNKNOWN";
  int required = snprintf(NULL, 0,
                          "provider_lock status=%s",
                          safe_status);
  if (required < 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger format failed");
    return SHOOTS_ERR_INVALID_STATE;
  }
  size_t payload_len = (size_t)required;
  if (payload_len > SHOOTS_LEDGER_MAX_BYTES) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger payload too large");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  char *payload = (char *)shoots_engine_alloc_internal(
      engine, payload_len + 1, out_error);
  if (payload == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  int written = snprintf(payload, payload_len + 1,
                         "provider_lock status=%s",
                         safe_status);
  if (written < 0) {
    shoots_engine_alloc_free_internal(engine, payload);
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger format failed");
    return SHOOTS_ERR_INVALID_STATE;
  }
  shoots_ledger_entry_t *entry = NULL;
  shoots_error_code_t status_code = shoots_ledger_append_internal(
      engine, SHOOTS_LEDGER_ENTRY_DECISION, payload, &entry, out_error);
  shoots_engine_alloc_free_internal(engine, payload);
  return status_code;
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
  size_t provider_id_len =
      strnlen(descriptor->provider_id, SHOOTS_PROVIDER_ID_MAX);
  if (provider_id_len != descriptor->provider_id_len) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider_id length mismatch");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  for (uint8_t index = 0; index < descriptor->provider_id_len; index++) {
    if (descriptor->provider_id[index] == '\0') {
      shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                       "provider_id contains null");
      return SHOOTS_ERR_INVALID_ARGUMENT;
    }
  }
  if (descriptor->provider_id[descriptor->provider_id_len] != '\0') {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider_id not terminated");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  for (size_t index = provider_id_len + 1; index < SHOOTS_PROVIDER_ID_MAX; index++) {
    if (descriptor->provider_id[index] != '\0') {
      shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                       "provider_id padding invalid");
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

shoots_error_code_t shoots_provider_register_internal(
  shoots_engine_t *engine,
  const shoots_provider_descriptor_t *descriptor,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (engine == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  char provider_id[SHOOTS_PROVIDER_ID_MAX];
  shoots_provider_format_id(descriptor, provider_id, sizeof(provider_id));
  shoots_error_code_t validation_status =
      shoots_provider_descriptor_validate(descriptor, out_error);
  if (validation_status != SHOOTS_OK) {
    shoots_provider_emit_register_entry(engine, provider_id, "REJECT",
                                        "invalid_descriptor", NULL);
    return validation_status;
  }
  if (engine->providers_locked) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider registry locked");
    shoots_provider_emit_register_entry(engine, provider_id, "REJECT", "locked", NULL);
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (engine->provider_count >= SHOOTS_ENGINE_MAX_PROVIDERS) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider registry full");
    shoots_provider_emit_register_entry(engine, provider_id, "REJECT",
                                        "registry_full", NULL);
    return SHOOTS_ERR_INVALID_STATE;
  }
  for (size_t index = 0; index < engine->provider_count; index++) {
    const shoots_provider_descriptor_t *existing = &engine->providers[index];
    if (existing->provider_id_len == descriptor->provider_id_len &&
        memcmp(existing->provider_id, descriptor->provider_id,
               descriptor->provider_id_len) == 0) {
      shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                       SHOOTS_SEVERITY_RECOVERABLE, "provider_id exists");
      shoots_provider_emit_register_entry(engine, provider_id, "REJECT",
                                          "provider_exists", NULL);
      return SHOOTS_ERR_INVALID_ARGUMENT;
    }
  }
  engine->providers[engine->provider_count] = *descriptor;
  engine->provider_count++;
  shoots_error_code_t ledger_status =
      shoots_provider_emit_register_entry(engine, provider_id, "ACCEPT", NULL,
                                          out_error);
  if (ledger_status != SHOOTS_OK) {
    return ledger_status;
  }
  return SHOOTS_OK;
}

shoots_error_code_t shoots_provider_registry_lock_internal(
  shoots_engine_t *engine,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (engine == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (engine->providers_locked) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider registry already locked");
    shoots_provider_emit_lock_entry(engine, "REJECT", NULL);
    return SHOOTS_ERR_INVALID_STATE;
  }
  engine->providers_locked = 1;
  return shoots_provider_emit_lock_entry(engine, "ACCEPT", out_error);
}

shoots_error_code_t shoots_provider_unregister_internal(
  shoots_engine_t *engine,
  const char *provider_id,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (engine == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  char provider_id_value[SHOOTS_PROVIDER_ID_MAX];
  shoots_provider_format_id_value(provider_id, provider_id_value,
                                  sizeof(provider_id_value));
  if (engine->providers_locked) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider registry locked");
    shoots_provider_emit_unregister_entry(engine, provider_id_value, "REJECT",
                                          "locked", NULL);
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (provider_id == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider_id is null");
    shoots_provider_emit_unregister_entry(engine, provider_id_value, "REJECT",
                                          "invalid_provider_id", NULL);
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  size_t provider_id_len = strnlen(provider_id, SHOOTS_PROVIDER_ID_MAX);
  if (provider_id_len == 0 || provider_id_len >= SHOOTS_PROVIDER_ID_MAX) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider_id invalid");
    shoots_provider_emit_unregister_entry(engine, provider_id_value, "REJECT",
                                          "invalid_provider_id", NULL);
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  size_t match_index = engine->provider_count;
  for (size_t index = 0; index < engine->provider_count; index++) {
    const shoots_provider_descriptor_t *existing = &engine->providers[index];
    if (existing->provider_id_len == provider_id_len &&
        memcmp(existing->provider_id, provider_id, provider_id_len) == 0) {
      match_index = index;
      break;
    }
  }
  if (match_index == engine->provider_count) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "provider not found");
    shoots_provider_emit_unregister_entry(engine, provider_id_value, "REJECT",
                                          "not_found", NULL);
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  for (size_t index = match_index + 1; index < engine->provider_count; index++) {
    engine->providers[index - 1] = engine->providers[index];
  }
  engine->provider_count--;
  memset(&engine->providers[engine->provider_count], 0,
         sizeof(engine->providers[engine->provider_count]));
  shoots_error_code_t ledger_status =
      shoots_provider_emit_unregister_entry(engine, provider_id_value, "ACCEPT",
                                            NULL, out_error);
  if (ledger_status != SHOOTS_OK) {
    return ledger_status;
  }
  return SHOOTS_OK;
}
