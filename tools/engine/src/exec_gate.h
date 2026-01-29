#ifndef SHOOTS_EXEC_GATE_H
#define SHOOTS_EXEC_GATE_H

#include "engine_internal.h"

shoots_error_code_t exec_gate_can_execute(
  shoots_engine_t *engine,
  shoots_session_t *session,
  const char *tool_id,
  const char **out_reason,
  shoots_error_info_t *out_error);

#endif
