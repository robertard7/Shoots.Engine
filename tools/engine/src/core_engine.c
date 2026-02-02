#include "core_engine.h"
#include "engine_internal.h"

void core_engine_initialize(shoots_engine_t *engine) {
    if (engine == NULL) {
        return;
    }
    engine->state = SHOOTS_ENGINE_STATE_INITIALIZED;
}

void core_engine_terminate(shoots_engine_t *engine) {
    if (engine == NULL) {
        return;
    }
    engine->state = SHOOTS_ENGINE_STATE_DESTROYED;
}
