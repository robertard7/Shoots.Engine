#ifndef SHOOTS_LEDGER_H
#define SHOOTS_LEDGER_H

#include "engine_internal.h"

shoots_error_code_t ledger_append(
  shoots_engine_t *engine,
  shoots_ledger_entry_type_t type,
  const char *entry,
  shoots_ledger_entry_t **out_entry,
  shoots_error_info_t *out_error);

shoots_error_code_t ledger_query_type(
  shoots_engine_t *engine,
  shoots_ledger_entry_type_t type,
  shoots_ledger_entry_t ***out_entries,
  size_t *out_count,
  shoots_error_info_t *out_error);

shoots_error_code_t ledger_provider_snapshot(
  shoots_engine_t *engine,
  char **out_snapshot,
  size_t *out_length,
  shoots_error_info_t *out_error);

#endif
