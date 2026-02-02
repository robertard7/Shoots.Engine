#include "commands.h"

#include <string.h>

void commands_add(shoots_engine_t *engine, const char *cmd) {
    if (engine == NULL || cmd == NULL || cmd[0] == '\0') {
        return;
    }
    if (engine->sessions_head == NULL) {
        return;
    }
    shoots_error_info_t error_info;
    shoots_command_record_t *record = NULL;
    (void)shoots_command_append_internal(
        engine,
        engine->sessions_head,
        0,
        cmd,
        "",
        0,
        0,
        &record,
        &error_info);
}

size_t commands_last(shoots_engine_t *engine, char *buf, size_t bufsize) {
    if (engine == NULL || buf == NULL || bufsize == 0) {
        return 0;
    }
    if (engine->commands_tail == NULL || engine->commands_tail->command_id == NULL) {
        return 0;
    }
    size_t copy_len = engine->commands_tail->command_id_len;
    if (copy_len >= bufsize) {
        copy_len = bufsize - 1;
    }
    if (copy_len > 0) {
        memcpy(buf, engine->commands_tail->command_id, copy_len);
    }
    buf[copy_len] = '\0';
    return copy_len;
}
