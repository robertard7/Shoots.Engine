#include "test_support.h"

int main(void) {
  shoots_error_info_t error;
  shoots_engine_t *engine = test_create_engine();

  char too_big[SHOOTS_LEDGER_MAX_BYTES + 2u];
  memset(too_big, 'X', sizeof(too_big) - 1u);
  too_big[sizeof(too_big) - 1u] = '\0';

  size_t ledger_before = engine->ledger_entry_count;
  shoots_ledger_entry_t *entry = NULL;
  shoots_error_code_t code = shoots_ledger_append_internal(engine,
                                                           SHOOTS_LEDGER_ENTRY_RESULT,
                                                           too_big,
                                                           &entry,
                                                           &error);
  assert(code == SHOOTS_ERR_INVALID_ARGUMENT);
  assert(entry == NULL);
  assert(engine->ledger_entry_count == ledger_before);

  shoots_provider_snapshot_t *snapshot = NULL;
  test_must_ok(shoots_engine_export_provider_snapshot_const(engine, &snapshot, &error),
               "snapshot after ledger failure",
               &error);
  assert(snapshot != NULL);
  assert(snapshot->payload != NULL);
  test_must_ok(shoots_engine_free(engine, snapshot->payload, &error), "free snapshot payload", &error);
  test_must_ok(shoots_engine_free(engine, snapshot, &error), "free snapshot", &error);

  test_must_ok(shoots_engine_destroy(engine, &error), "destroy engine", &error);
  return 0;
}
