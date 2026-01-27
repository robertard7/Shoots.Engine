#include "planner.h"
#include <string.h>

void planner_plan(shoots_engine_t *engine, const char *request) {
    strncpy(engine->plan_buffer, request, sizeof(engine->plan_buffer) - 1);
    engine->plan_buffer[sizeof(engine->plan_buffer) - 1] = '\0';
}

void planner_free_response(shoots_engine_t *engine) {
    engine->plan_buffer[0] = '\0';
}
