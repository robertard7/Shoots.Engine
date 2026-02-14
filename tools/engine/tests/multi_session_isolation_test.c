#include "test_support.h"

int main(void) {
  shoots_error_info_t error;
  shoots_engine_t *engine = test_create_engine();
  shoots_provider_descriptor_t provider;
  test_register_provider_tool_and_lock(engine, &provider);

  shoots_session_t *session_a = test_create_session_with_plan(engine, "intent-A", 1);
  shoots_session_t *session_b = test_create_session_with_plan(engine, "intent-B", 1);

  shoots_provider_request_t req_a1 = test_mint_request(engine, session_a, &provider, 1, 1, 0x3001ULL);
  shoots_provider_request_t req_b1 = test_mint_request(engine, session_b, &provider, 1, 1, 0x3002ULL);

  shoots_provider_request_record_t *pending = NULL;
  size_t pending_count = 0;
  test_must_ok(shoots_engine_export_pending_provider_requests_const(engine,
                                                                    &pending,
                                                                    &pending_count,
                                                                    &error),
               "pending export",
               &error);
  assert(pending_count == 2);
  int found_a = 0;
  int found_b = 0;
  for (size_t i = 0; i < pending_count; i++) {
    if (pending[i].session_id == session_a->session_id) {
      found_a = 1;
    }
    if (pending[i].session_id == session_b->session_id) {
      found_b = 1;
    }
  }
  assert(found_a && found_b);
  test_must_ok(shoots_engine_free(engine, pending, &error), "free pending", &error);

  shoots_provider_receipt_t receipt_a = test_make_receipt_success(&req_a1);
  test_must_ok(shoots_provider_receipt_import_internal(engine, &receipt_a, &error),
               "import session A receipt",
               &error);

  pending = NULL;
  pending_count = 0;
  test_must_ok(shoots_engine_export_pending_provider_requests_const(engine,
                                                                    &pending,
                                                                    &pending_count,
                                                                    &error),
               "pending export after session A",
               &error);
  assert(pending_count == 1);
  assert(pending[0].session_id == session_b->session_id);
  assert(pending[0].request_id == req_b1.request_id);
  test_must_ok(shoots_engine_free(engine, pending, &error), "free pending after A", &error);

  shoots_provider_receipt_t receipt_b = test_make_receipt_success(&req_b1);
  test_must_ok(shoots_provider_receipt_import_internal(engine, &receipt_b, &error),
               "import session B receipt",
               &error);
  assert(test_pending_count(engine) == 0);

  test_must_ok(shoots_engine_destroy(engine, &error), "destroy engine", &error);
  return 0;
}
