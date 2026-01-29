#include "engine_internal.h"

#include <string.h>

#ifndef NDEBUG
#include <assert.h>
#endif

static void shoots_session_error_set(shoots_error_info_t *out_error,
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

static void shoots_session_plan_record_clear(shoots_session_t *session,
                                             shoots_plan_record_t *record) {
  if (session == NULL || record == NULL || session->engine == NULL) {
    return;
  }
  if (record->tool_ids != NULL) {
    for (size_t index = 0; index < record->tool_count; index++) {
      shoots_engine_alloc_free_internal(session->engine, record->tool_ids[index]);
      record->tool_ids[index] = NULL;
    }
    shoots_engine_alloc_free_internal(session->engine, record->tool_ids);
    record->tool_ids = NULL;
  }
  if (record->rejection_reasons != NULL) {
    shoots_engine_alloc_free_internal(session->engine, record->rejection_reasons);
    record->rejection_reasons = NULL;
  }
  record->tool_count = 0;
  record->plan_id = 0;
  record->plan_hash = 0;
}

void shoots_session_plan_clear_internal(shoots_session_t *session) {
  if (session == NULL) {
    return;
  }
  for (size_t index = 0; index < SHOOTS_SESSION_MAX_PLANS; index++) {
    shoots_session_plan_record_clear(session, &session->plans[index]);
  }
  session->plan_count = 0;
}

shoots_error_code_t shoots_session_plan_store_internal(
  shoots_session_t *session,
  uint64_t plan_id,
  uint64_t plan_hash,
  const char *const *tool_ids,
  const shoots_tool_reject_reason_t *rejection_reasons,
  size_t tool_count,
  shoots_error_info_t *out_error) {
  if (session == NULL || session->engine == NULL) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                             SHOOTS_SEVERITY_RECOVERABLE, "session is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (plan_id == 0) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                             SHOOTS_SEVERITY_RECOVERABLE, "plan_id invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (tool_count > 0 && (tool_ids == NULL || rejection_reasons == NULL)) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                             SHOOTS_SEVERITY_RECOVERABLE, "plan tools invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (tool_count > SHOOTS_SESSION_PLAN_MAX_TOOLS) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                             SHOOTS_SEVERITY_RECOVERABLE, "plan tool count invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }

  size_t slot = 0;
  int found = 0;
  for (size_t index = 0; index < session->plan_count; index++) {
    if (session->plans[index].plan_id == plan_id) {
      slot = index;
      found = 1;
      break;
    }
  }
  if (!found) {
    if (session->plan_count < SHOOTS_SESSION_MAX_PLANS) {
      slot = session->plan_count;
      session->plan_count++;
    } else {
      slot = 0;
    }
  }

  shoots_plan_record_t *record = &session->plans[slot];
  shoots_session_plan_record_clear(session, record);

  if (tool_count > 0) {
    char **tool_copy = (char **)shoots_engine_alloc_internal(
        session->engine, tool_count * sizeof(*tool_copy), out_error);
    if (tool_copy == NULL) {
      return SHOOTS_ERR_OUT_OF_MEMORY;
    }
    shoots_tool_reject_reason_t *reason_copy =
        (shoots_tool_reject_reason_t *)shoots_engine_alloc_internal(
            session->engine, tool_count * sizeof(*reason_copy), out_error);
    if (reason_copy == NULL) {
      shoots_engine_alloc_free_internal(session->engine, tool_copy);
      return SHOOTS_ERR_OUT_OF_MEMORY;
    }
    for (size_t index = 0; index < tool_count; index++) {
      tool_copy[index] = NULL;
    }
    for (size_t index = 0; index < tool_count; index++) {
      const char *tool_id = tool_ids[index];
      if (tool_id == NULL || tool_id[0] == '\0') {
        shoots_engine_alloc_free_internal(session->engine, reason_copy);
        for (size_t cleanup = 0; cleanup < tool_count; cleanup++) {
          shoots_engine_alloc_free_internal(session->engine, tool_copy[cleanup]);
        }
        shoots_engine_alloc_free_internal(session->engine, tool_copy);
        shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                                 SHOOTS_SEVERITY_RECOVERABLE, "plan tool_id invalid");
        return SHOOTS_ERR_INVALID_ARGUMENT;
      }
      size_t tool_len = strlen(tool_id);
      if (tool_len < SHOOTS_TOOL_ID_MIN_LEN || tool_len > SHOOTS_TOOL_ID_MAX_LEN) {
        shoots_engine_alloc_free_internal(session->engine, reason_copy);
        for (size_t cleanup = 0; cleanup < tool_count; cleanup++) {
          shoots_engine_alloc_free_internal(session->engine, tool_copy[cleanup]);
        }
        shoots_engine_alloc_free_internal(session->engine, tool_copy);
        shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                                 SHOOTS_SEVERITY_RECOVERABLE, "plan tool_id length invalid");
        return SHOOTS_ERR_INVALID_ARGUMENT;
      }
      char *tool_id_copy = (char *)shoots_engine_alloc_internal(
          session->engine, tool_len + 1, out_error);
      if (tool_id_copy == NULL) {
        shoots_engine_alloc_free_internal(session->engine, reason_copy);
        for (size_t cleanup = 0; cleanup < tool_count; cleanup++) {
          shoots_engine_alloc_free_internal(session->engine, tool_copy[cleanup]);
        }
        shoots_engine_alloc_free_internal(session->engine, tool_copy);
        return SHOOTS_ERR_OUT_OF_MEMORY;
      }
      memcpy(tool_id_copy, tool_id, tool_len + 1);
      tool_copy[index] = tool_id_copy;
      reason_copy[index] = rejection_reasons[index];
      reason_copy[index].token[SHOOTS_TOOL_REASON_TOKEN_MAX - 1] = '\0';
      if (reason_copy[index].code < SHOOTS_TOOL_REJECT_OK ||
          reason_copy[index].code > SHOOTS_TOOL_REJECT_INVALID_DESCRIPTOR) {
        shoots_engine_alloc_free_internal(session->engine, reason_copy);
        for (size_t cleanup = 0; cleanup < tool_count; cleanup++) {
          shoots_engine_alloc_free_internal(session->engine, tool_copy[cleanup]);
        }
        shoots_engine_alloc_free_internal(session->engine, tool_copy);
        shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                                 SHOOTS_SEVERITY_RECOVERABLE, "plan reject code invalid");
        return SHOOTS_ERR_INVALID_ARGUMENT;
      }
    }
    record->tool_ids = tool_copy;
    record->rejection_reasons = reason_copy;
    record->tool_count = tool_count;
  }

  record->plan_id = plan_id;
  record->plan_hash = plan_hash;
  if (session->next_plan_id <= plan_id && session->next_plan_id != 0) {
    if (plan_id == UINT64_MAX) {
      session->next_plan_id = 0;
    } else {
      session->next_plan_id = plan_id + 1;
    }
  }
  return SHOOTS_OK;
}

shoots_error_code_t shoots_session_transition_active_internal(
  shoots_session_t *session,
  uint64_t execution_slot,
  shoots_error_info_t *out_error) {
  if (session == NULL) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                             SHOOTS_SEVERITY_RECOVERABLE, "session is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (execution_slot == 0) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                             SHOOTS_SEVERITY_RECOVERABLE, "execution_slot is invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (session->has_active_execution) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_STATE,
                             SHOOTS_SEVERITY_RECOVERABLE, "execution already active");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (session->has_terminal_execution &&
      execution_slot <= session->terminal_execution_slot) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_STATE,
                             SHOOTS_SEVERITY_RECOVERABLE, "execution slot terminal");
    return SHOOTS_ERR_INVALID_STATE;
  }
#ifndef NDEBUG
  if (session->has_terminal_execution) {
    assert(session->terminal_execution_slot < execution_slot);
  }
#endif
  session->has_active_execution = 1;
  session->active_execution_slot = execution_slot;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_session_transition_terminal_internal(
  shoots_session_t *session,
  uint64_t execution_slot,
  shoots_error_info_t *out_error) {
  if (session == NULL) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                             SHOOTS_SEVERITY_RECOVERABLE, "session is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (execution_slot == 0) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT,
                             SHOOTS_SEVERITY_RECOVERABLE, "execution_slot is invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (!session->has_active_execution ||
      session->active_execution_slot != execution_slot) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_STATE,
                             SHOOTS_SEVERITY_RECOVERABLE, "execution slot not active");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (session->has_terminal_execution &&
      execution_slot <= session->terminal_execution_slot) {
    shoots_session_error_set(out_error, SHOOTS_ERR_INVALID_STATE,
                             SHOOTS_SEVERITY_RECOVERABLE, "execution slot terminal");
    return SHOOTS_ERR_INVALID_STATE;
  }
#ifndef NDEBUG
  if (session->has_terminal_execution) {
    assert(session->terminal_execution_slot < execution_slot);
  }
#endif
  session->has_active_execution = 0;
  session->active_execution_slot = 0;
  session->has_terminal_execution = 1;
  session->terminal_execution_slot = execution_slot;
  return SHOOTS_OK;
}
