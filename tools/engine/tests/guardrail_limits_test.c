#include "engine_internal.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static shoots_engine_t *create_engine(void) {
  shoots_config_t config;
  memset(&config, 0, sizeof(config));
  config.model_root_path = ".";
  config.max_memory_bytes = 1024u * 1024u;
  config.max_execution_steps = 1024u;

  shoots_engine_t *engine = NULL;
  shoots_error_info_t error;
  shoots_error_code_t code = shoots_engine_create(&config, &engine, &error);
  assert(code == SHOOTS_OK);
  return engine;
}

static void test_ledger_size_cap(shoots_engine_t *engine) {
  shoots_error_info_t error;
  shoots_ledger_entry_t *entry = NULL;
  char *payload = (char *)malloc(SHOOTS_LEDGER_MAX_BYTES + 2);
  assert(payload != NULL);
  memset(payload, 'x', SHOOTS_LEDGER_MAX_BYTES + 1);
  payload[SHOOTS_LEDGER_MAX_BYTES + 1] = '\0';
  shoots_error_code_t code = shoots_ledger_append_internal(engine,
                                                           SHOOTS_LEDGER_ENTRY_RESULT,
                                                           payload,
                                                           &entry,
                                                           &error);
  assert(code == SHOOTS_ERR_INVALID_ARGUMENT);
  assert(entry == NULL);
  free(payload);
}

static void test_snapshot_export_bounds(shoots_engine_t *engine) {
  shoots_error_info_t error;
  shoots_error_code_t code = shoots_engine_export_provider_snapshot_const(engine,
                                                                          NULL,
                                                                          &error);
  assert(code == SHOOTS_ERR_INVALID_ARGUMENT);

  shoots_provider_snapshot_t *snapshot = NULL;
  code = shoots_engine_export_provider_snapshot_const(engine, &snapshot, &error);
  assert(code == SHOOTS_OK);
  assert(snapshot != NULL);
  assert(snapshot->payload != NULL);
  assert(snapshot->payload_len > 0);
  code = shoots_engine_free(engine, snapshot->payload, &error);
  assert(code == SHOOTS_OK);
  code = shoots_engine_free(engine, snapshot, &error);
  assert(code == SHOOTS_OK);
}

static void test_pending_export_order(shoots_engine_t *engine) {
  shoots_error_info_t error;
  shoots_provider_descriptor_t provider;
  memset(&provider, 0, sizeof(provider));
  provider.provider_id_len = 5;
  memcpy(provider.provider_id, "provA", provider.provider_id_len + 1);
  provider.supported_tool_categories = SHOOTS_PROVIDER_TOOL_CATEGORY_EXECUTION;
  provider.max_concurrency = 8;
  provider.guarantees_mask = SHOOTS_PROVIDER_GUARANTEE_DETERMINISTIC;
  assert(shoots_provider_register_internal(engine, &provider, &error) == SHOOTS_OK);

  engine->tools_locked = 0;
  shoots_tool_constraints_t constraints = {8, 64, SHOOTS_TOOL_CONFIRM_NONE};
  shoots_tool_record_t *tool_record = NULL;
  assert(shoots_tool_register_internal(engine,
                                       "tool.exec",
                                       SHOOTS_TOOL_CATEGORY_EXECUTION,
                                       1,
                                       0x3u,
                                       &constraints,
                                       SHOOTS_TOOL_DETERMINISM_DETERMINISTIC,
                                       &tool_record,
                                       &error) == SHOOTS_OK);
  assert(tool_record != NULL);
  engine->tools_locked = 1;
  assert(shoots_provider_registry_lock_internal(engine, &error) == SHOOTS_OK);

  for (int i = 0; i < 2; i++) {
    char intent_id[32];
    snprintf(intent_id, sizeof(intent_id), "intent-limit-%d", i);
    shoots_session_t *session = NULL;
    assert(shoots_session_create_internal(engine,
                                          intent_id,
                                          SHOOTS_SESSION_MODE_TRANSACTIONAL,
                                          &session,
                                          &error) == SHOOTS_OK);
    const char *tool_ids[1] = {"tool.exec"};
    shoots_tool_reject_reason_t reasons[1];
    memset(reasons, 0, sizeof(reasons));
    reasons[0].code = SHOOTS_TOOL_REJECT_OK;
    memcpy(reasons[0].token, "ok", 3);
    assert(shoots_session_plan_store_internal(session,
                                              1,
                                              0x424242ULL,
                                              tool_ids,
                                              reasons,
                                              1,
                                              &error) == SHOOTS_OK);
    shoots_provider_request_t request;
    memset(&request, 0, sizeof(request));
    const uint8_t arg_blob[] = {0x41, 0x42, 0x43};
    assert(shoots_provider_request_mint_internal(engine,
                                                 session,
                                                 1,
                                                 1,
                                                 "tool.exec",
                                                 &provider,
                                                 0x1u,
                                                 0x1000ULL + (uint64_t)i,
                                                 arg_blob,
                                                 (uint32_t)sizeof(arg_blob),
                                                 &request,
                                                 &error) == SHOOTS_OK);
  }

  shoots_provider_request_record_t *pending = NULL;
  size_t pending_count = 0;
  assert(shoots_engine_export_pending_provider_requests_const(engine,
                                                              &pending,
                                                              &pending_count,
                                                              &error) == SHOOTS_OK);
  assert(pending_count == 2);
  assert(pending[0].request_id <= pending[1].request_id);
  assert(shoots_engine_free(engine, pending, &error) == SHOOTS_OK);
}

int main(void) {
  shoots_error_info_t error;
  shoots_engine_t *engine = create_engine();
  test_ledger_size_cap(engine);
  test_snapshot_export_bounds(engine);
  test_pending_export_order(engine);
  assert(shoots_engine_destroy(engine, &error) == SHOOTS_OK);
  return 0;
}
