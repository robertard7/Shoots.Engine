#include "engine_internal.h"

static void core_engine_initialize(shoots_engine_t *engine) {
    if (engine == NULL) {
        return;
    }
    engine->state = SHOOTS_ENGINE_STATE_INITIALIZED;
}

static void core_engine_terminate(shoots_engine_t *engine) {
    if (engine == NULL) {
        return;
    }
    engine->state = SHOOTS_ENGINE_STATE_DESTROYED;
}
