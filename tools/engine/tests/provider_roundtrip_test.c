#include "engine_internal.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void must_ok(shoots_error_code_t code, const char *step, shoots_error_info_t *error) {
  if (code == SHOOTS_OK) {
    return;
  }
  fprintf(stderr, "%s failed: code=%d message=%s\n", step, (int)code,
          (error != NULL && error->message != NULL) ? error->message : "(none)");
  assert(0 && "roundtrip step failed");
}

static shoots_engine_t *create_engine_or_die(void) {
  shoots_config_t config;
  memset(&config, 0, sizeof(config));
  config.model_root_path = ".";
  config.max_memory_bytes = 1024u * 1024u;
  config.max_execution_steps = 1024u;
  shoots_engine_t *engine = NULL;
  shoots_error_info_t error;
  shoots_error_code_t code = shoots_engine_create(&config, &engine, &error);
  must_ok(code, "shoots_engine_create", &error);
  return engine;
}

static void setup_provider_roundtrip(
  shoots_engine_t *engine,
  shoots_session_t **out_session,
  shoots_provider_descriptor_t *out_provider,
  shoots_provider_request_t *out_request) {
  shoots_error_info_t error;
  shoots_tool_record_t *tool_record = NULL;
  shoots_session_t *session = NULL;
  shoots_provider_descriptor_t provider;
  memset(&provider, 0, sizeof(provider));
  provider.provider_id_len = 5;
  memcpy(provider.provider_id, "provA", provider.provider_id_len + 1);
  provider.supported_tool_categories = SHOOTS_PROVIDER_TOOL_CATEGORY_EXECUTION;
  provider.max_concurrency = 8;
  provider.guarantees_mask = SHOOTS_PROVIDER_GUARANTEE_DETERMINISTIC;

  must_ok(shoots_provider_register_internal(engine, &provider, &error),
          "shoots_provider_register_internal", &error);

  engine->tools_locked = 0;
  shoots_tool_constraints_t constraints;
  constraints.max_args = 8;
  constraints.max_bytes = 64;
  constraints.confirm_policy = SHOOTS_TOOL_CONFIRM_NONE;
  must_ok(shoots_tool_register_internal(engine,
                                        "tool.exec",
                                        SHOOTS_TOOL_CATEGORY_EXECUTION,
                                        1,
                                        0x3u,
                                        &constraints,
                                        SHOOTS_TOOL_DETERMINISM_DETERMINISTIC,
                                        &tool_record,
                                        &error),
          "shoots_tool_register_internal", &error);
  assert(tool_record != NULL);
  engine->tools_locked = 1;
  must_ok(shoots_provider_registry_lock_internal(engine, &error),
          "shoots_provider_registry_lock_internal", &error);

  must_ok(shoots_session_create_internal(engine,
                                         "intent-provider-roundtrip",
                                         SHOOTS_SESSION_MODE_TRANSACTIONAL,
                                         &session,
                                         &error),
          "shoots_session_create_internal", &error);
  assert(session != NULL);

  const char *tool_ids[1] = {"tool.exec"};
  shoots_tool_reject_reason_t reasons[1];
  memset(&reasons, 0, sizeof(reasons));
  reasons[0].code = SHOOTS_TOOL_REJECT_OK;
  memcpy(reasons[0].token, "ok", 3);
  must_ok(shoots_session_plan_store_internal(session,
                                             1,
                                             0x424242ULL,
                                             tool_ids,
                                             reasons,
                                             1,
                                             &error),
          "shoots_session_plan_store_internal", &error);

  const uint8_t arg_blob[] = {0x41, 0x42, 0x43};
  must_ok(shoots_provider_request_mint_internal(engine,
                                                session,
                                                1,
                                                1,
                                                "tool.exec",
                                                &provider,
                                                0x1u,
                                                0x1111ULL,
                                                arg_blob,
                                                (uint32_t)sizeof(arg_blob),
                                                out_request,
                                                &error),
          "shoots_provider_request_mint_internal", &error);

  *out_session = session;
  *out_provider = provider;
}

int main(void) {
  shoots_engine_t *engine = create_engine_or_die();
  shoots_error_info_t error;
  shoots_session_t *session = NULL;
  shoots_provider_descriptor_t provider;
  shoots_provider_request_t request;
  memset(&request, 0, sizeof(request));

  setup_provider_roundtrip(engine, &session, &provider, &request);

  shoots_provider_request_record_t *pending = NULL;
  size_t pending_count = 0;
  must_ok(shoots_engine_export_pending_provider_requests_const(engine,
                                                               &pending,
                                                               &pending_count,
                                                               &error),
          "shoots_engine_export_pending_provider_requests_const(before)",
          &error);
  assert(pending_count == 1);
  assert(pending != NULL);
  must_ok(shoots_engine_free(engine, pending, &error), "shoots_engine_free(pending-before)", &error);

  size_t ledger_before = engine->ledger_entry_count;

  shoots_provider_receipt_t receipt;
  memset(&receipt, 0, sizeof(receipt));
  receipt.session_id = request.session_id;
  receipt.plan_id = request.plan_id;
  receipt.execution_slot = request.execution_slot;
  receipt.request_id = request.request_id;
  receipt.provider_id_len = request.provider_id_len;
  memcpy(receipt.provider_id, request.provider_id, request.provider_id_len + 1);
  receipt.tool_id_len = request.tool_id_len;
  memcpy(receipt.tool_id, request.tool_id, request.tool_id_len + 1);
  receipt.tool_version = request.tool_version;
  receipt.input_hash = request.input_hash;
  receipt.result_code = SHOOTS_PROVIDER_RESULT_SUCCESS;
  receipt.output_size = 2;
  receipt.output_blob[0] = 0x4f;
  receipt.output_blob[1] = 0x4b;

  must_ok(shoots_provider_receipt_import_internal(engine, &receipt, &error),
          "shoots_provider_receipt_import_internal", &error);

  pending = NULL;
  pending_count = 0;
  must_ok(shoots_engine_export_pending_provider_requests_const(engine,
                                                               &pending,
                                                               &pending_count,
                                                               &error),
          "shoots_engine_export_pending_provider_requests_const(after)",
          &error);
  assert(pending_count == 0);
  assert(pending == NULL);

  assert(engine->ledger_entry_count > ledger_before);
  assert(session->has_terminal_execution == 1);
  assert(session->terminal_execution_slot == 1);
  assert(session->has_active_execution == 0);

  must_ok(shoots_engine_destroy(engine, &error), "shoots_engine_destroy", &error);
  return 0;
}
