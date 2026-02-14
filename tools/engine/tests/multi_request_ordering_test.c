#include "test_support.h"

static void run_scenario(char **out_ledger) {
  shoots_error_info_t error;
  shoots_engine_t *engine = test_create_engine();
  shoots_provider_descriptor_t provider;
  test_register_provider_tool_and_lock(engine, &provider);

  shoots_session_t *session_a = test_create_session_with_plan(engine, "intent-order-A", 1);
  shoots_session_t *session_b = test_create_session_with_plan(engine, "intent-order-B", 1);
  shoots_session_t *session_c = test_create_session_with_plan(engine, "intent-order-C", 1);

  shoots_provider_request_t requests[3];
  requests[0] = test_mint_request(engine, session_a, &provider, 1, 1, 0x2001ULL);
  requests[1] = test_mint_request(engine, session_b, &provider, 1, 1, 0x2002ULL);
  requests[2] = test_mint_request(engine, session_c, &provider, 1, 1, 0x2003ULL);

  shoots_provider_request_record_t *pending = NULL;
  size_t pending_count = 0;
  test_must_ok(shoots_engine_export_pending_provider_requests_const(engine,
                                                                    &pending,
                                                                    &pending_count,
                                                                    &error),
               "pending export",
               &error);
  assert(pending_count == 3);
  for (size_t i = 1; i < pending_count; i++) {
    assert(pending[i - 1].request_id <= pending[i].request_id);
  }
  test_must_ok(shoots_engine_free(engine, pending, &error), "free pending", &error);

  shoots_provider_receipt_t receipt2 = test_make_receipt_success(&requests[1]);
  shoots_provider_receipt_t receipt0 = test_make_receipt_success(&requests[0]);
  shoots_provider_receipt_t receipt1 = test_make_receipt_success(&requests[2]);

  test_must_ok(shoots_provider_receipt_import_internal(engine, &receipt2, &error),
               "import receipt B",
               &error);
  test_must_ok(shoots_provider_receipt_import_internal(engine, &receipt0, &error),
               "import receipt A",
               &error);
  test_must_ok(shoots_provider_receipt_import_internal(engine, &receipt1, &error),
               "import receipt C",
               &error);
  assert(test_pending_count(engine) == 0);

  *out_ledger = test_serialize_ledger(engine);
  test_must_ok(shoots_engine_destroy(engine, &error), "destroy engine", &error);
}

int main(void) {
  char *first = NULL;
  char *second = NULL;
  run_scenario(&first);
  run_scenario(&second);
  assert(strcmp(first, second) == 0);
  free(first);
  free(second);
  return 0;
}
