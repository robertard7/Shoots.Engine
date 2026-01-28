#include "engine_internal.h"

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
