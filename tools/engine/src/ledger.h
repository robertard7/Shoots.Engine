#ifndef SHOOTS_LEDGER_H
#define SHOOTS_LEDGER_H

#include "engine_internal.h"

void ledger_append(shoots_engine_t *engine, const char *entry);
void ledger_query_type(shoots_engine_t *engine, ledger_type_t type, ledger_result_t *out);

#endif
