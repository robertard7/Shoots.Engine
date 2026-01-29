#include "exec_gate.h"

shoots_error_code_t exec_gate_can_execute(
  shoots_engine_t *engine,
  shoots_session_t *session,
  const char *tool_id,
  const char **out_reason,
  shoots_error_info_t *out_error) {
  shoots_error_code_t status =
      shoots_engine_can_execute_internal(engine, session, tool_id,
                                         out_reason, out_error);
  if (status != SHOOTS_OK && out_reason != NULL && *out_reason == NULL) {
    *out_reason = "execution rejected";
  }
  return status;
}
