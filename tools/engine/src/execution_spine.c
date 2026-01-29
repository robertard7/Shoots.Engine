#include "execution_spine.h"

shoots_error_code_t spine_record_intent(
  shoots_engine_t *engine,
  const char *intent_id,
  shoots_session_mode_t mode,
  shoots_session_t **out_session,
  shoots_error_info_t *out_error) {
  return shoots_session_create_internal(engine, intent_id, mode, out_session, out_error);
}

shoots_error_code_t spine_record_result(
  shoots_engine_t *engine,
  shoots_session_t *session,
  const char *command_id,
  shoots_result_status_t status,
  const char *payload,
  shoots_result_record_t **out_record,
  shoots_error_info_t *out_error) {
  return shoots_result_append_internal(engine, session, command_id,
                                       status, payload, out_record, out_error);
}
