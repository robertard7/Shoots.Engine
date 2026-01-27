#include "ledger.h"
#include <string.h>

void ledger_append(shoots_engine_t *engine, const char *entry) {
    size_t idx = engine->ledger_count % MAX_LEDGER;
    strncpy(engine->ledger[idx].text, entry, sizeof(engine->ledger[idx].text) - 1);
    engine->ledger[idx].text[sizeof(engine->ledger[idx].text) - 1] = '\0';
    engine->ledger_count++;
}

void ledger_query_type(shoots_engine_t *engine, ledger_type_t type, ledger_result_t *out) {
    out->count = 0;
    for (size_t i = 0; i < MAX_LEDGER && out->count < MAX_RESULTS; i++) {
        if (engine->ledger[i].type == type) {
            out->entries[out->count++] = &engine->ledger[i];
        }
    }
}
