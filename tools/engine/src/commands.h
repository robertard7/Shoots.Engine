#ifndef SHOOTS_COMMANDS_H
#define SHOOTS_COMMANDS_H

#include "engine_internal.h"

void commands_add(shoots_engine_t *engine, const char *cmd);
size_t commands_last(shoots_engine_t *engine, char *buf, size_t bufsize);

#endif
