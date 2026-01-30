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

shoots_error_code_t spine_mint_provider_request(
  shoots_engine_t *engine,
  shoots_session_t *session,
  uint64_t plan_id,
  uint64_t execution_slot,
  const char *tool_id,
  const shoots_provider_descriptor_t *provider,
  uint64_t capability_mask,
  uint64_t input_hash,
  const uint8_t *arg_blob,
  uint32_t arg_size,
  shoots_provider_request_t *out_request,
  shoots_error_info_t *out_error) {
  return shoots_provider_request_mint_internal(
      engine, session, plan_id, execution_slot, tool_id, provider,
      capability_mask, input_hash, arg_blob, arg_size, out_request, out_error);
}

shoots_error_code_t spine_verify_provider_receipt(
  shoots_engine_t *engine,
  const shoots_provider_receipt_t *receipt,
  shoots_error_info_t *out_error) {
  return shoots_provider_receipt_verify_internal(engine, receipt, out_error);
}
