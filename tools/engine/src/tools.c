#include "tools.h"
#include <string.h>
#ifndef NDEBUG
#include <assert.h>
#endif

#ifndef NDEBUG
static void tools_assert_descriptor_bounds(
  const char *tool_id,
  uint32_t version,
  uint64_t capabilities,
  const shoots_tool_constraints_t *constraints,
  uint32_t determinism_flags) {
  size_t tool_id_len = tool_id != NULL ? strlen(tool_id) : 0;
  assert(tool_id_len >= SHOOTS_TOOL_ID_MIN_LEN);
  assert(tool_id_len <= SHOOTS_TOOL_ID_MAX_LEN);
  assert(version >= SHOOTS_TOOL_VERSION_MIN);
  assert(version <= SHOOTS_TOOL_VERSION_MAX);
  assert((determinism_flags & ~SHOOTS_TOOL_DETERMINISM_MASK) == 0u);
  assert((capabilities & ~SHOOTS_TOOL_CAPABILITIES_ALLOWED) == 0u);
  if (constraints != NULL) {
    assert(constraints->max_args <= SHOOTS_TOOL_MAX_ARGS);
    assert(constraints->max_bytes <= SHOOTS_TOOL_MAX_BYTES);
    assert(constraints->confirm_policy >= SHOOTS_TOOL_CONFIRM_NONE);
    assert(constraints->confirm_policy <= SHOOTS_TOOL_CONFIRM_ON_FAIL);
  }
}
#endif

static void tools_set_error(shoots_error_info_t *out_error,
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

static void tools_emit_registration_error(shoots_engine_t *engine, const char *message) {
  if (engine == NULL || message == NULL || message[0] == '\0') {
    return;
  }
  shoots_ledger_entry_t *entry = NULL;
  shoots_ledger_append_internal(engine, SHOOTS_LEDGER_ENTRY_ERROR,
                                message, &entry, NULL);
}

static shoots_error_code_t tools_validate_registration(
  shoots_engine_t *engine,
  const char *tool_id,
  uint32_t version,
  uint64_t capabilities,
  const shoots_tool_constraints_t *constraints,
  uint32_t determinism_flags,
  shoots_error_info_t *out_error) {
  shoots_tool_constraints_t local_constraints = {0, 0, SHOOTS_TOOL_CONFIRM_NONE};
  if (engine == NULL) {
    tools_set_error(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                    SHOOTS_SEVERITY_RECOVERABLE, "engine is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (tool_id == NULL || tool_id[0] == '\0') {
    tools_emit_registration_error(engine, "tool registration rejected: tool_id invalid");
    tools_set_error(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                    SHOOTS_SEVERITY_RECOVERABLE, "tool_id is null or empty");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  size_t tool_id_len = strlen(tool_id);
  if (tool_id_len < SHOOTS_TOOL_ID_MIN_LEN || tool_id_len > SHOOTS_TOOL_ID_MAX_LEN) {
    tools_emit_registration_error(engine, "tool registration rejected: tool_id length");
    tools_set_error(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                    SHOOTS_SEVERITY_RECOVERABLE, "tool_id length invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (version < SHOOTS_TOOL_VERSION_MIN || version > SHOOTS_TOOL_VERSION_MAX) {
    tools_emit_registration_error(engine, "tool registration rejected: version invalid");
    tools_set_error(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                    SHOOTS_SEVERITY_RECOVERABLE, "tool version invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if ((determinism_flags & ~SHOOTS_TOOL_DETERMINISM_MASK) != 0u) {
    tools_emit_registration_error(engine,
                                  "tool registration rejected: determinism flags invalid");
    tools_set_error(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                    SHOOTS_SEVERITY_RECOVERABLE, "determinism flags invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if ((capabilities & ~SHOOTS_TOOL_CAPABILITIES_ALLOWED) != 0u) {
    tools_emit_registration_error(engine,
                                  "tool registration rejected: capabilities invalid");
    tools_set_error(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                    SHOOTS_SEVERITY_RECOVERABLE, "capabilities invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (constraints != NULL) {
    local_constraints = *constraints;
  }
  if (local_constraints.max_args > SHOOTS_TOOL_MAX_ARGS ||
      local_constraints.max_bytes > SHOOTS_TOOL_MAX_BYTES) {
    tools_emit_registration_error(engine, "tool registration rejected: constraints invalid");
    tools_set_error(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                    SHOOTS_SEVERITY_RECOVERABLE, "constraints invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (local_constraints.confirm_policy < SHOOTS_TOOL_CONFIRM_NONE ||
      local_constraints.confirm_policy > SHOOTS_TOOL_CONFIRM_ON_FAIL) {
    tools_emit_registration_error(engine, "tool registration rejected: confirm policy invalid");
    tools_set_error(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                    SHOOTS_SEVERITY_RECOVERABLE, "confirm policy invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  return SHOOTS_OK;
}

shoots_error_code_t tools_register(
  shoots_engine_t *engine,
  const char *tool_id,
  shoots_tool_category_t category,
  uint32_t version,
  uint64_t capabilities,
  const shoots_tool_constraints_t *constraints,
  uint32_t determinism_flags,
  shoots_tool_record_t **out_record,
  shoots_error_info_t *out_error) {
  shoots_error_code_t status = tools_validate_registration(
      engine, tool_id, version, capabilities, constraints, determinism_flags, out_error);
  if (status != SHOOTS_OK) {
    if (out_record != NULL) {
      *out_record = NULL;
    }
    return status;
  }
#ifndef NDEBUG
  tools_assert_descriptor_bounds(tool_id, version, capabilities, constraints, determinism_flags);
#endif
  return shoots_tool_register_internal(engine, tool_id, category, version,
                                       capabilities, constraints,
                                       determinism_flags, out_record, out_error);
}

shoots_error_code_t tools_invoke(
  shoots_engine_t *engine,
  const char *tool_id,
  shoots_error_info_t *out_error) {
  return shoots_tool_invoke_internal(engine, tool_id, out_error);
}
