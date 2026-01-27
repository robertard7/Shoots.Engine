#include "engine_internal.h"

#include <stdlib.h>
#include <string.h>

#define SHOOTS_ENGINE_MAGIC 0x53484f4fu
#define SHOOTS_ALLOC_MAGIC 0x53484f41u

typedef struct shoots_alloc_header {
  size_t payload_size;
  size_t total_size;
  uint32_t magic;
  struct shoots_alloc_header *next;
} shoots_alloc_header_t;

static void shoots_error_clear(shoots_error_info_t *out_error) {
  if (out_error == NULL) {
    return;
  }
  out_error->code = SHOOTS_OK;
  out_error->severity = SHOOTS_SEVERITY_RECOVERABLE;
  out_error->message = NULL;
}

static void shoots_error_set(shoots_error_info_t *out_error,
                             shoots_error_code_t code,
                             shoots_error_severity_t severity,
                             const char *message) {
  if (out_error == NULL) {
    return;
  }
  out_error->code = code;
  out_error->severity = severity;
  out_error->message = message;
}

static shoots_error_code_t shoots_validate_config(const shoots_config_t *config,
                                                  shoots_error_info_t *out_error) {
  if (config == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "config is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (config->model_root_path == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "model_root_path is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (config->allow_background_threads > 1 || config->allow_filesystem_io > 1 ||
      config->allow_network_io > 1) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "allow flags must be 0 or 1");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  return SHOOTS_OK;
}

static shoots_error_code_t shoots_reserve_memory(shoots_engine_t *engine,
                                                 size_t bytes,
                                                 shoots_error_info_t *out_error) {
  if (engine == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine is null");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (engine->memory_used_bytes > engine->memory_limit_bytes) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "memory accounting invalid");
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  if (bytes > engine->memory_limit_bytes - engine->memory_used_bytes) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "memory limit exceeded");
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  if (bytes > SIZE_MAX - engine->memory_used_bytes) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "memory accounting overflow");
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  engine->memory_used_bytes += bytes;
  return SHOOTS_OK;
}

static void shoots_release_memory(shoots_engine_t *engine, size_t bytes) {
  if (engine == NULL) {
    return;
  }
  if (bytes > engine->memory_used_bytes) {
    engine->memory_used_bytes = 0;
    return;
  }
  engine->memory_used_bytes -= bytes;
}

static void *shoots_engine_alloc(shoots_engine_t *engine,
                                 size_t bytes,
                                 shoots_error_info_t *out_error) {
  if (bytes > SIZE_MAX - sizeof(shoots_alloc_header_t)) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "allocation size overflow");
    return NULL;
  }
  size_t total = bytes + sizeof(shoots_alloc_header_t);
  shoots_error_code_t reserve = shoots_reserve_memory(engine, total, out_error);
  if (reserve != SHOOTS_OK) {
    return NULL;
  }
  shoots_alloc_header_t *header = (shoots_alloc_header_t *)malloc(total);
  if (header == NULL) {
    shoots_release_memory(engine, total);
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "allocation failed");
    return NULL;
  }
  header->payload_size = bytes;
  header->total_size = total;
  header->magic = SHOOTS_ALLOC_MAGIC;
  header->next = (shoots_alloc_header_t *)engine->allocations_head;
  engine->allocations_head = header;
  return (void *)(header + 1);
}

static void shoots_engine_alloc_free(shoots_engine_t *engine, void *buffer) {
  if (buffer == NULL) {
    return;
  }
  shoots_alloc_header_t *header = ((shoots_alloc_header_t *)buffer) - 1;
  if (header->magic != SHOOTS_ALLOC_MAGIC) {
    return;
  }
  shoots_alloc_header_t **cursor = (shoots_alloc_header_t **)&engine->allocations_head;
  while (*cursor != NULL) {
    if (*cursor == header) {
      *cursor = header->next;
      break;
    }
    cursor = &(*cursor)->next;
  }
  shoots_release_memory(engine, header->total_size);
  header->magic = 0;
  free(header);
}

static void shoots_engine_release_all(shoots_engine_t *engine) {
  shoots_alloc_header_t *cursor = (shoots_alloc_header_t *)engine->allocations_head;
  while (cursor != NULL) {
    shoots_alloc_header_t *next = cursor->next;
    shoots_release_memory(engine, cursor->total_size);
    cursor->magic = 0;
    free(cursor);
    cursor = next;
  }
  engine->allocations_head = NULL;
}

shoots_error_code_t shoots_engine_create(const shoots_config_t *config,
                                         shoots_engine_t **out_engine,
                                         shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_engine == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "out_engine is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_engine = NULL;

  shoots_error_code_t validation = shoots_validate_config(config, out_error);
  if (validation != SHOOTS_OK) {
    return validation;
  }

  if (config->max_memory_bytes < sizeof(shoots_engine_t)) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "max_memory_bytes too small");
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }

  shoots_engine_t *engine = (shoots_engine_t *)malloc(sizeof(*engine));
  if (engine == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine allocation failed");
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }

  memset(engine, 0, sizeof(*engine));
  engine->memory_limit_bytes = config->max_memory_bytes;
  engine->memory_used_bytes = sizeof(*engine);
  engine->state = SHOOTS_ENGINE_STATE_INITIALIZED;
  engine->magic = SHOOTS_ENGINE_MAGIC;
  engine->allocations_head = NULL;

  engine->config = *config;
  engine->model_root_path = NULL;

  size_t path_len = strlen(config->model_root_path);
  char *path_copy = (char *)shoots_engine_alloc(engine, path_len + 1, out_error);
  if (path_copy == NULL) {
    shoots_engine_destroy(engine, NULL);
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memcpy(path_copy, config->model_root_path, path_len + 1);
  engine->model_root_path = path_copy;
  engine->config.model_root_path = engine->model_root_path;

  *out_engine = engine;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_engine_destroy(shoots_engine_t *engine,
                                          shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (engine == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (engine->magic != SHOOTS_ENGINE_MAGIC ||
      engine->state != SHOOTS_ENGINE_STATE_INITIALIZED) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine state invalid");
    return SHOOTS_ERR_INVALID_STATE;
  }

  engine->state = SHOOTS_ENGINE_STATE_DESTROYED;
  engine->magic = 0;

  engine->model_root_path = NULL;
  shoots_engine_release_all(engine);

  free(engine);
  return SHOOTS_OK;
}

shoots_error_code_t shoots_engine_free(shoots_engine_t *engine,
                                       void *buffer,
                                       shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (engine == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (engine->magic != SHOOTS_ENGINE_MAGIC ||
      engine->state != SHOOTS_ENGINE_STATE_INITIALIZED) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine state invalid");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (buffer == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "buffer is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  shoots_alloc_header_t *header = ((shoots_alloc_header_t *)buffer) - 1;
  if (header->magic != SHOOTS_ALLOC_MAGIC) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "buffer not owned by engine");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  shoots_engine_alloc_free(engine, buffer);
  return SHOOTS_OK;
}
