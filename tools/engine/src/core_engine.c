#include "core_engine.h"
#include "engine_internal.h"

void core_engine_initialize(shoots_engine_t *engine) {
    engine->initialized = 1;
}

void core_engine_terminate(shoots_engine_t *engine) {
    engine->initialized = 0;
}
