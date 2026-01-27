#include "execution_spine.h"

void spine_record_intent(shoots_engine_t *engine, intent_t intent) {
    if (engine->intent_count < MAX_INTENTS) {
        engine->intents[engine->intent_count++] = intent;
    }
}

void spine_record_result(shoots_engine_t *engine, result_t result) {
    if (engine->result_count < MAX_RESULTS) {
        engine->results[engine->result_count++] = result;
    }
}
