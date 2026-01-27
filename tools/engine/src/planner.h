#ifndef SHOOTS_PLANNER_H
#define SHOOTS_PLANNER_H

#include "engine_internal.h"

void planner_plan(shoots_engine_t *engine, const char *request);
void planner_free_response(shoots_engine_t *engine);

#endif
