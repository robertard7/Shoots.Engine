#include "commands.h"
#include <string.h>

void commands_add(shoots_engine_t *engine, const char *cmd) {
    size_t idx = engine->command_count % MAX_COMMANDS;
    strncpy(engine->commands[idx], cmd, sizeof(engine->commands[idx]) - 1);
    engine->commands[idx][sizeof(engine->commands[idx]) - 1] = '\0';
    engine->command_count++;
}

size_t commands_last(shoots_engine_t *engine, char *buf, size_t bufsize) {
    if (engine->command_count == 0) return 0;
    size_t idx = (engine->command_count - 1) % MAX_COMMANDS;
    strncpy(buf, engine->commands[idx], bufsize - 1);
    buf[bufsize - 1] = '\0';
    return strlen(buf);
}
