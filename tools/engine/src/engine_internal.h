#ifndef SHOOTS_ENGINE_INTERNAL_H
#define SHOOTS_ENGINE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "shoots/shoots.h"

typedef enum shoots_engine_state {
  SHOOTS_ENGINE_STATE_UNINITIALIZED = 0,
  SHOOTS_ENGINE_STATE_INITIALIZED = 1,
  SHOOTS_ENGINE_STATE_DESTROYED = 2
} shoots_engine_state_t;

struct shoots_engine {
  shoots_config_t config;
  char *model_root_path;
  size_t memory_used_bytes;
  size_t memory_limit_bytes;
  void *allocations_head;
  shoots_engine_state_t state;
  uint32_t magic;
};

#endif
