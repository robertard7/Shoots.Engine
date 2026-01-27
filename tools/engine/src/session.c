#include "session.h"
#include <string.h>

void session_init(shoots_engine_t *engine) {
    memset(engine->sessions, 0, sizeof(engine->sessions));
}

void session_close(shoots_engine_t *engine, session_id_t id) {
    if (id < MAX_SESSIONS) {
        engine->sessions[id].active = 0;
    }
}
