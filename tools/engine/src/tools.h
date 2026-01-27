#ifndef SHOOTS_TOOLS_H
#define SHOOTS_TOOLS_H

#include "engine_internal.h"

tool_id_t tools_register(shoots_engine_t *engine, const char *name);
void tools_invoke(shoots_engine_t *engine, tool_id_t id);

#endif
