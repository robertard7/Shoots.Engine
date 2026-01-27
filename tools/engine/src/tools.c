#include "tools.h"
#include <string.h>

tool_id_t tools_register(shoots_engine_t *engine, const char *name) {
    if (engine->tool_count < MAX_TOOLS) {
        strncpy(engine->tool_names[engine->tool_count], name, MAX_TOOL_NAME - 1);
        return engine->tool_count++;
    }
    return INVALID_TOOL;
}

void tools_invoke(shoots_engine_t *engine, tool_id_t id) {
    (void)engine;
    (void)id;
}
