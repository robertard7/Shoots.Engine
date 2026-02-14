#include "test_support.h"

int main(void) {
  shoots_error_info_t error;
  shoots_engine_t *engine = test_create_engine();
  shoots_provider_descriptor_t provider;
  test_register_provider_tool_and_lock(engine, &provider);
  shoots_session_t *session = test_create_session_with_plan(engine, "intent-malformed", 1);
  shoots_provider_request_t request = test_mint_request(engine, session, &provider, 1, 1, 0x1111ULL);

  size_t pending_before = test_pending_count(engine);
  assert(pending_before == 1);
  size_t ledger_before = engine->ledger_entry_count;

  shoots_provider_receipt_t bad = test_make_receipt_success(&request);

  bad.request_id = request.request_id + 1;
  assert(shoots_provider_receipt_import_internal(engine, &bad, &error) != SHOOTS_OK);
  assert(test_pending_count(engine) == pending_before);

  bad = test_make_receipt_success(&request);
  bad.session_id = request.session_id + 1;
  assert(shoots_provider_receipt_import_internal(engine, &bad, &error) != SHOOTS_OK);
  assert(test_pending_count(engine) == pending_before);

  bad = test_make_receipt_success(&request);
  bad.execution_slot = request.execution_slot + 1;
  assert(shoots_provider_receipt_import_internal(engine, &bad, &error) != SHOOTS_OK);
  assert(test_pending_count(engine) == pending_before);

  bad = test_make_receipt_success(&request);
  bad.output_size = SHOOTS_PROVIDER_OUTPUT_MAX_BYTES + 1u;
  assert(shoots_provider_receipt_import_internal(engine, &bad, &error) != SHOOTS_OK);
  assert(test_pending_count(engine) == pending_before);

  shoots_provider_receipt_t good = test_make_receipt_success(&request);
  test_must_ok(shoots_provider_receipt_import_internal(engine, &good, &error),
               "import good receipt",
               &error);
  assert(test_pending_count(engine) == 0);
  size_t ledger_after_first_good = engine->ledger_entry_count;

  assert(shoots_provider_receipt_import_internal(engine, &good, &error) != SHOOTS_OK);
  assert(test_pending_count(engine) == 0);
  assert(engine->ledger_entry_count == ledger_after_first_good + 1);
  assert(engine->ledger_entry_count >= ledger_before);

  test_must_ok(shoots_engine_destroy(engine, &error), "shoots_engine_destroy", &error);
  return 0;
}
