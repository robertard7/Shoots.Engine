#ifndef SHOOTS_ENGINE_INTERNAL_H
#define SHOOTS_ENGINE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "shoots/shoots.h"

typedef struct shoots_provider_runtime shoots_provider_runtime_t;

typedef enum shoots_engine_state {
  SHOOTS_ENGINE_STATE_UNINITIALIZED = 0,
  SHOOTS_ENGINE_STATE_INITIALIZED = 1,
  SHOOTS_ENGINE_STATE_DESTROYED = 2
} shoots_engine_state_t;

typedef enum shoots_model_state {
  SHOOTS_MODEL_STATE_UNLOADED = 0,
  SHOOTS_MODEL_STATE_LOADED = 1,
  SHOOTS_MODEL_STATE_DESTROYED = 2
} shoots_model_state_t;

struct shoots_model {
  uint32_t magic;
  shoots_engine_t *engine;
  shoots_model_state_t state;
  struct shoots_model *next;
};

struct shoots_engine {
  shoots_config_t config;
  char *model_root_path;
  size_t memory_used_bytes;
  size_t memory_limit_bytes;
  void *allocations_head;
  shoots_provider_runtime_t *provider_runtime;
  struct shoots_model *models_head;
  struct shoots_model *models_tail;
  shoots_engine_state_t state;
  uint32_t magic;
};

void *shoots_engine_alloc_internal(shoots_engine_t *engine,
                                   size_t bytes,
                                   shoots_error_info_t *out_error);

void shoots_engine_alloc_free_internal(shoots_engine_t *engine, void *buffer);

#endif
