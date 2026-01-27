#include "exec_gate.h"

int exec_gate_can_execute(shoots_engine_t *engine) {
    return engine->initialized;
}
