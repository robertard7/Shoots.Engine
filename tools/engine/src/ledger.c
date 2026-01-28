#include "ledger.h"

shoots_error_code_t ledger_append(
  shoots_engine_t *engine,
  shoots_ledger_entry_type_t type,
  const char *entry,
  shoots_ledger_entry_t **out_entry,
  shoots_error_info_t *out_error) {
  return shoots_ledger_append_internal(engine, type, entry, out_entry, out_error);
}

shoots_error_code_t ledger_query_type(
  shoots_engine_t *engine,
  shoots_ledger_entry_type_t type,
  shoots_ledger_entry_t ***out_entries,
  size_t *out_count,
  shoots_error_info_t *out_error) {
  return shoots_ledger_query_type_internal(engine, type, out_entries, out_count, out_error);
}
