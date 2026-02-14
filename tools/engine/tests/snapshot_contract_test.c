#include "test_support.h"

static void test_snapshot_repeatability(shoots_engine_t *engine) {
  shoots_error_info_t error;
  shoots_provider_snapshot_t *first = NULL;
  shoots_provider_snapshot_t *second = NULL;

  test_must_ok(shoots_engine_export_provider_snapshot_const(engine, &first, &error),
               "snapshot export first",
               &error);
  test_must_ok(shoots_engine_export_provider_snapshot_const(engine, &second, &error),
               "snapshot export second",
               &error);

  assert(first != NULL && second != NULL);
  assert(first->payload != NULL && second->payload != NULL);
  assert(first->payload_len == second->payload_len);
  assert(memcmp(first->payload, second->payload, first->payload_len) == 0);
  assert(first->payload_len <= SHOOTS_LEDGER_MAX_BYTES);
  assert(strstr(first->payload, "providers count=") == first->payload);

  test_must_ok(shoots_engine_free(engine, first->payload, &error), "free snapshot payload 1", &error);
  test_must_ok(shoots_engine_free(engine, first, &error), "free snapshot 1", &error);
  test_must_ok(shoots_engine_free(engine, second->payload, &error), "free snapshot payload 2", &error);
  test_must_ok(shoots_engine_free(engine, second, &error), "free snapshot 2", &error);
}

int main(void) {
  shoots_error_info_t error;
  shoots_engine_t *engine = test_create_engine();
  shoots_provider_descriptor_t provider;
  test_register_provider_tool_and_lock(engine, &provider);
  shoots_session_t *session = test_create_session_with_plan(engine, "intent-snapshot", 1);
  shoots_provider_request_t request = test_mint_request(engine, session, &provider, 1, 1, 0x4444ULL);

  size_t pending_before = test_pending_count(engine);
  size_t ledger_before = engine->ledger_entry_count;
  test_snapshot_repeatability(engine);
  assert(test_pending_count(engine) == pending_before);
  assert(engine->ledger_entry_count == ledger_before);

  shoots_provider_receipt_t receipt = test_make_receipt_success(&request);
  test_must_ok(shoots_provider_receipt_import_internal(engine, &receipt, &error),
               "import receipt",
               &error);

  test_snapshot_repeatability(engine);
  assert(engine->ledger_entry_count >= ledger_before);

  test_must_ok(shoots_engine_destroy(engine, &error), "destroy engine", &error);
  return 0;
}
