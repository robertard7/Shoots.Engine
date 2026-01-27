#include "engine_internal.h"
#include "provider_runtime.h"

#include <stdlib.h>
#include <string.h>
#ifndef NDEBUG
#include <assert.h>
#endif

#define SHOOTS_ENGINE_MAGIC 0x53484f4fu
#define SHOOTS_ENGINE_MAGIC_DESTROYED 0x44454ad1u
#define SHOOTS_ALLOC_MAGIC 0x53484f41u
#define SHOOTS_MODEL_MAGIC 0x53484f4du
#define SHOOTS_MODEL_MAGIC_DESTROYED 0x4d4f4444u
#define SHOOTS_SESSION_MAGIC 0x53485353u
#define SHOOTS_SESSION_MAGIC_DESTROYED 0x53445353u
#define SHOOTS_SESSION_CHAT_CAPACITY 4096u

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

static void shoots_assert_invariants(const shoots_engine_t *engine) {
#ifndef NDEBUG
  if (engine == NULL) {
    return;
  }
  assert(engine->memory_used_bytes <= engine->memory_limit_bytes);
  if (engine->state == SHOOTS_ENGINE_STATE_INITIALIZED &&
      engine->allocations_head == NULL) {
    assert(engine->memory_used_bytes == sizeof(*engine));
  }
  if (engine->state == SHOOTS_ENGINE_STATE_DESTROYED) {
    assert(engine->allocations_head == NULL);
    assert(engine->memory_used_bytes == 0);
    assert(engine->memory_limit_bytes == 0);
  }
  const shoots_alloc_header_t *slow = (const shoots_alloc_header_t *)engine->allocations_head;
  const shoots_alloc_header_t *fast = (const shoots_alloc_header_t *)engine->allocations_head;
  while (fast != NULL && fast->next != NULL) {
    slow = slow->next;
    fast = fast->next->next;
    assert(slow != fast);
  }
  const shoots_alloc_header_t *cursor =
      (const shoots_alloc_header_t *)engine->allocations_head;
  while (cursor != NULL) {
    assert(cursor->magic == SHOOTS_ALLOC_MAGIC);
    cursor = cursor->next;
  }
  if (engine->models_head == NULL) {
    assert(engine->models_tail == NULL);
  } else {
    assert(engine->models_tail != NULL);
    assert(engine->models_tail->next == NULL);
  }
  if (engine->sessions_head == NULL) {
    assert(engine->sessions_tail == NULL);
  } else {
    assert(engine->sessions_tail != NULL);
    assert(engine->sessions_tail->next == NULL);
    const shoots_session_t *cursor = engine->sessions_head;
    while (cursor != NULL) {
      assert(cursor->chat_capacity == SHOOTS_SESSION_CHAT_CAPACITY);
      assert(cursor->chat_head < cursor->chat_capacity || cursor->chat_capacity == 0);
      assert(cursor->chat_size <= cursor->chat_capacity);
      cursor = cursor->next;
    }
  }
#endif
}

static shoots_error_code_t shoots_validate_engine(shoots_engine_t *engine,
                                                  shoots_error_info_t *out_error) {
  if (engine == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (engine->magic == SHOOTS_ENGINE_MAGIC_DESTROYED) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine destroyed");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (engine->magic != SHOOTS_ENGINE_MAGIC) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine handle invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (engine->state != SHOOTS_ENGINE_STATE_INITIALIZED) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "engine state invalid");
    return SHOOTS_ERR_INVALID_STATE;
  }
  return SHOOTS_OK;
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

static shoots_error_code_t shoots_validate_model(shoots_engine_t *engine,
                                                 shoots_model_t *model,
                                                 shoots_error_info_t *out_error) {
  if (model == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "model is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (model->magic == SHOOTS_MODEL_MAGIC_DESTROYED) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "model destroyed");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (model->magic != SHOOTS_MODEL_MAGIC) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "model handle invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (model->engine != engine) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "model owned by different engine");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (model->state != SHOOTS_MODEL_STATE_LOADED) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "model state invalid");
    return SHOOTS_ERR_INVALID_STATE;
  }
  return SHOOTS_OK;
}

static shoots_error_code_t shoots_validate_session(shoots_engine_t *engine,
                                                   shoots_session_t *session,
                                                   shoots_error_info_t *out_error) {
  if (session == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "session is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (session->magic == SHOOTS_SESSION_MAGIC_DESTROYED) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "session destroyed");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (session->magic != SHOOTS_SESSION_MAGIC) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "session handle invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (session->engine != engine) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "session owned by different engine");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (session->chat_capacity != SHOOTS_SESSION_CHAT_CAPACITY) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "session chat buffer invalid");
    return SHOOTS_ERR_INVALID_STATE;
  }
  return SHOOTS_OK;
}

static void shoots_register_model(shoots_engine_t *engine, shoots_model_t *model) {
  if (engine->models_tail == NULL) {
    engine->models_head = model;
    engine->models_tail = model;
    return;
  }
  engine->models_tail->next = model;
  engine->models_tail = model;
}

static int shoots_unregister_model(shoots_engine_t *engine, shoots_model_t *model) {
  shoots_model_t *prev = NULL;
  shoots_model_t *cursor = engine->models_head;
  while (cursor != NULL) {
    if (cursor == model) {
      if (prev == NULL) {
        engine->models_head = cursor->next;
      } else {
        prev->next = cursor->next;
      }
      if (engine->models_tail == cursor) {
        engine->models_tail = prev;
      }
      cursor->next = NULL;
      return 1;
    }
    prev = cursor;
    cursor = cursor->next;
  }
  return 0;
}

static void shoots_register_session(shoots_engine_t *engine, shoots_session_t *session) {
  if (engine->sessions_tail == NULL) {
    engine->sessions_head = session;
    engine->sessions_tail = session;
    return;
  }
  engine->sessions_tail->next = session;
  engine->sessions_tail = session;
}

static shoots_session_t *shoots_find_session(shoots_engine_t *engine, uint64_t session_id) {
  shoots_session_t *cursor = engine->sessions_head;
  while (cursor != NULL) {
    if (cursor->session_id == session_id) {
      return cursor;
    }
    cursor = cursor->next;
  }
  return NULL;
}

static shoots_error_code_t shoots_reserve_memory(shoots_engine_t *engine,
                                                 size_t bytes,
                                                 shoots_error_info_t *out_error) {
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
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
  shoots_assert_invariants(engine);
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

void *shoots_engine_alloc_internal(shoots_engine_t *engine,
                                   size_t bytes,
                                   shoots_error_info_t *out_error) {
#ifndef NDEBUG
  size_t prior_memory_used = 0;
  void *prior_allocations_head = NULL;
  if (engine != NULL) {
    prior_memory_used = engine->memory_used_bytes;
    prior_allocations_head = engine->allocations_head;
  }
#endif
  if (bytes > SIZE_MAX - sizeof(shoots_alloc_header_t)) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "allocation size overflow");
#ifndef NDEBUG
    if (engine != NULL) {
      assert(engine->memory_used_bytes == prior_memory_used);
      assert(engine->allocations_head == prior_allocations_head);
    }
#endif
    return NULL;
  }
  size_t total = bytes + sizeof(shoots_alloc_header_t);
  shoots_error_code_t reserve = shoots_reserve_memory(engine, total, out_error);
  if (reserve != SHOOTS_OK) {
#ifndef NDEBUG
    if (engine != NULL) {
      assert(engine->memory_used_bytes == prior_memory_used);
      assert(engine->allocations_head == prior_allocations_head);
    }
#endif
    return NULL;
  }
  shoots_alloc_header_t *header = (shoots_alloc_header_t *)malloc(total);
  if (header == NULL) {
    shoots_release_memory(engine, total);
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "allocation failed");
#ifndef NDEBUG
    if (engine != NULL) {
      assert(engine->memory_used_bytes == prior_memory_used);
      assert(engine->allocations_head == prior_allocations_head);
    }
#endif
    return NULL;
  }
  header->payload_size = bytes;
  header->total_size = total;
  header->magic = SHOOTS_ALLOC_MAGIC;
  header->next = (shoots_alloc_header_t *)engine->allocations_head;
  engine->allocations_head = header;
  shoots_assert_invariants(engine);
  return (void *)(header + 1);
}

void shoots_engine_alloc_free_internal(shoots_engine_t *engine, void *buffer) {
  if (buffer == NULL) {
    return;
  }
  shoots_alloc_header_t *header = ((shoots_alloc_header_t *)buffer) - 1;
  if (header->magic != SHOOTS_ALLOC_MAGIC) {
    return;
  }
  shoots_alloc_header_t **cursor = (shoots_alloc_header_t **)&engine->allocations_head;
  int found = 0;
  while (*cursor != NULL) {
    if (*cursor == header) {
      *cursor = header->next;
      found = 1;
      break;
    }
    cursor = &(*cursor)->next;
  }
  if (!found) {
    return;
  }
  shoots_release_memory(engine, header->total_size);
  shoots_assert_invariants(engine);
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
  shoots_assert_invariants(engine);
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
  engine->provider_runtime = NULL;
  engine->models_head = NULL;
  engine->models_tail = NULL;
  engine->sessions_head = NULL;
  engine->sessions_tail = NULL;
  engine->next_session_id = 1;

  engine->config = *config;
  engine->model_root_path = NULL;

  size_t path_len = strlen(config->model_root_path);
  char *path_copy = (char *)shoots_engine_alloc_internal(
      engine, path_len + 1, out_error);
  if (path_copy == NULL) {
    shoots_engine_destroy(engine, NULL);
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memcpy(path_copy, config->model_root_path, path_len + 1);
  engine->model_root_path = path_copy;
  engine->config.model_root_path = engine->model_root_path;

  shoots_error_code_t runtime_status = shoots_provider_runtime_create(
      engine, &engine->config, &engine->provider_runtime, out_error);
  if (runtime_status != SHOOTS_OK) {
    shoots_engine_destroy(engine, NULL);
    return runtime_status;
  }

  *out_engine = engine;
  shoots_assert_invariants(engine);
  return SHOOTS_OK;
}

shoots_error_code_t shoots_engine_destroy(shoots_engine_t *engine,
                                          shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  if (engine->models_head != NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "models still loaded");
    return SHOOTS_ERR_INVALID_STATE;
  }

  if (engine->provider_runtime != NULL) {
    shoots_error_code_t runtime_status = shoots_provider_runtime_validate_ready(
        engine->provider_runtime, out_error);
    if (runtime_status != SHOOTS_OK) {
      return runtime_status;
    }
    runtime_status = shoots_provider_runtime_destroy(
        engine, engine->provider_runtime, out_error);
    if (runtime_status != SHOOTS_OK) {
      return runtime_status;
    }
    if (engine->provider_runtime != NULL) {
      shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                       "provider runtime still attached");
      return SHOOTS_ERR_INVALID_STATE;
    }
  }

  shoots_assert_invariants(engine);
  engine->state = SHOOTS_ENGINE_STATE_DESTROYED;
  engine->magic = SHOOTS_ENGINE_MAGIC_DESTROYED;

  engine->model_root_path = NULL;
  shoots_engine_release_all(engine);
  memset(&engine->config, 0, sizeof(engine->config));
  engine->sessions_head = NULL;
  engine->sessions_tail = NULL;
  engine->next_session_id = 0;
  engine->memory_used_bytes = 0;
  engine->memory_limit_bytes = 0;
  shoots_assert_invariants(engine);
  return SHOOTS_OK;
}

shoots_error_code_t shoots_engine_free(shoots_engine_t *engine,
                                       void *buffer,
                                       shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  if (buffer == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "buffer is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (buffer == engine->provider_runtime) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "buffer not owned by engine");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  shoots_alloc_header_t *header = ((shoots_alloc_header_t *)buffer) - 1;
  if (header->magic != SHOOTS_ALLOC_MAGIC) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "buffer not owned by engine");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  shoots_alloc_header_t *cursor = (shoots_alloc_header_t *)engine->allocations_head;
  int found = 0;
  while (cursor != NULL) {
    if (cursor == header) {
      found = 1;
      break;
    }
    cursor = cursor->next;
  }
  if (!found) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "buffer not owned by engine");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  shoots_engine_alloc_free_internal(engine, buffer);
  return SHOOTS_OK;
}

shoots_error_code_t shoots_model_load(shoots_engine_t *engine,
                                      const char *model_identifier,
                                      shoots_model_t **out_model,
                                      shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_model == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "out_model is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_model = NULL;
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  if (model_identifier == NULL || model_identifier[0] == '\0') {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "model_identifier is null or empty");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }

  shoots_model_t *model = (shoots_model_t *)shoots_engine_alloc_internal(
      engine, sizeof(*model), out_error);
  if (model == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memset(model, 0, sizeof(*model));
  model->magic = SHOOTS_MODEL_MAGIC;
  model->engine = engine;
  model->state = SHOOTS_MODEL_STATE_LOADED;
  model->next = NULL;
  shoots_register_model(engine, model);
  shoots_assert_invariants(engine);
  *out_model = model;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_model_unload(shoots_engine_t *engine,
                                        shoots_model_t *model,
                                        shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  shoots_error_code_t model_status = shoots_validate_model(engine, model, out_error);
  if (model_status != SHOOTS_OK) {
    return model_status;
  }
  if (!shoots_unregister_model(engine, model)) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "model not registered");
    return SHOOTS_ERR_INVALID_STATE;
  }
  model->state = SHOOTS_MODEL_STATE_DESTROYED;
  model->magic = SHOOTS_MODEL_MAGIC_DESTROYED;
  shoots_engine_alloc_free_internal(engine, model);
  shoots_assert_invariants(engine);
  return SHOOTS_OK;
}

shoots_error_code_t shoots_session_create_internal(
  shoots_engine_t *engine,
  const char *intent_id,
  shoots_session_mode_t mode,
  shoots_session_t **out_session,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_session == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "out_session is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_session = NULL;
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  if (intent_id == NULL || intent_id[0] == '\0') {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "intent_id is null or empty");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (mode < SHOOTS_SESSION_MODE_UNSPECIFIED ||
      mode > SHOOTS_SESSION_MODE_TRANSACTIONAL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "session mode invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (engine->next_session_id == 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "session id exhausted");
    return SHOOTS_ERR_INVALID_STATE;
  }

  shoots_session_t *session = (shoots_session_t *)shoots_engine_alloc_internal(
      engine, sizeof(*session), out_error);
  if (session == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memset(session, 0, sizeof(*session));
  session->magic = SHOOTS_SESSION_MAGIC;
  session->engine = engine;
  session->state = SHOOTS_SESSION_STATE_ACTIVE;
  session->mode = mode;
  session->session_id = engine->next_session_id;
  if (engine->next_session_id == UINT64_MAX) {
    engine->next_session_id = 0;
  } else {
    engine->next_session_id++;
  }

  size_t intent_len = strlen(intent_id);
  char *intent_copy = (char *)shoots_engine_alloc_internal(
      engine, intent_len + 1, out_error);
  if (intent_copy == NULL) {
    session->magic = SHOOTS_SESSION_MAGIC_DESTROYED;
    shoots_engine_alloc_free_internal(engine, session);
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memcpy(intent_copy, intent_id, intent_len + 1);
  session->intent_id = intent_copy;
  session->last_error = NULL;
  session->chat_capacity = SHOOTS_SESSION_CHAT_CAPACITY;
  session->chat_size = 0;
  session->chat_head = 0;
  session->chat_buffer = (char *)shoots_engine_alloc_internal(
      engine, session->chat_capacity, out_error);
  if (session->chat_buffer == NULL) {
    session->magic = SHOOTS_SESSION_MAGIC_DESTROYED;
    shoots_engine_alloc_free_internal(engine, session->intent_id);
    session->intent_id = NULL;
    shoots_engine_alloc_free_internal(engine, session);
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memset(session->chat_buffer, 0, session->chat_capacity);
  session->next = NULL;

  shoots_register_session(engine, session);
  shoots_assert_invariants(engine);
  *out_session = session;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_session_attach_internal(
  shoots_engine_t *engine,
  uint64_t session_id,
  shoots_session_t **out_session,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_session == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "out_session is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_session = NULL;
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  if (session_id == 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "session_id is invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  shoots_session_t *session = shoots_find_session(engine, session_id);
  if (session == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "session not found");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  shoots_error_code_t session_status = shoots_validate_session(engine, session, out_error);
  if (session_status != SHOOTS_OK) {
    return session_status;
  }
  if (session->state != SHOOTS_SESSION_STATE_ACTIVE) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "session not active");
    return SHOOTS_ERR_INVALID_STATE;
  }
  *out_session = session;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_session_close_internal(
  shoots_engine_t *engine,
  shoots_session_t *session,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  shoots_error_code_t session_status = shoots_validate_session(engine, session, out_error);
  if (session_status != SHOOTS_OK) {
    return session_status;
  }
  if (session->state != SHOOTS_SESSION_STATE_ACTIVE) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "session not active");
    return SHOOTS_ERR_INVALID_STATE;
  }
  session->state = SHOOTS_SESSION_STATE_CLOSED;
  shoots_assert_invariants(engine);
  return SHOOTS_OK;
}

shoots_error_code_t shoots_session_chat_append_internal(
  shoots_session_t *session,
  const char *text,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (session == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "session is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (text == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "text is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (text[0] == '\0') {
    return SHOOTS_OK;
  }
  shoots_error_code_t session_status =
      shoots_validate_session(session->engine, session, out_error);
  if (session_status != SHOOTS_OK) {
    return session_status;
  }
  if (session->state != SHOOTS_SESSION_STATE_ACTIVE) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "session not active");
    return SHOOTS_ERR_INVALID_STATE;
  }
  size_t text_len = strlen(text);
  if (session->chat_capacity == 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "chat buffer disabled");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (text_len >= session->chat_capacity) {
    const char *slice = text + (text_len - session->chat_capacity);
    memcpy(session->chat_buffer, slice, session->chat_capacity);
    session->chat_head = 0;
    session->chat_size = session->chat_capacity;
    shoots_assert_invariants(session->engine);
    return SHOOTS_OK;
  }
  if (session->chat_size + text_len > session->chat_capacity) {
    size_t overflow = session->chat_size + text_len - session->chat_capacity;
    session->chat_head =
        (session->chat_head + overflow) % session->chat_capacity;
    session->chat_size = session->chat_capacity - text_len;
  }
  size_t tail = (session->chat_head + session->chat_size) % session->chat_capacity;
  size_t first_chunk = session->chat_capacity - tail;
  if (first_chunk > text_len) {
    first_chunk = text_len;
  }
  memcpy(session->chat_buffer + tail, text, first_chunk);
  if (first_chunk < text_len) {
    memcpy(session->chat_buffer, text + first_chunk, text_len - first_chunk);
  }
  session->chat_size += text_len;
  shoots_assert_invariants(session->engine);
  return SHOOTS_OK;
}

shoots_error_code_t shoots_session_chat_snapshot_internal(
  shoots_session_t *session,
  char **out_buffer,
  size_t *out_length,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_buffer == NULL || out_length == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "output is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_buffer = NULL;
  *out_length = 0;
  if (session == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "session is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  shoots_error_code_t session_status =
      shoots_validate_session(session->engine, session, out_error);
  if (session_status != SHOOTS_OK) {
    return session_status;
  }
  if (session->chat_size == 0) {
    return SHOOTS_OK;
  }
  size_t snapshot_len = session->chat_size;
  if (snapshot_len > SIZE_MAX - 1) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "snapshot size overflow");
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  char *buffer = (char *)shoots_engine_alloc_internal(
      session->engine, snapshot_len + 1, out_error);
  if (buffer == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  size_t first_chunk = session->chat_capacity - session->chat_head;
  if (first_chunk > snapshot_len) {
    first_chunk = snapshot_len;
  }
  memcpy(buffer, session->chat_buffer + session->chat_head, first_chunk);
  if (first_chunk < snapshot_len) {
    memcpy(buffer + first_chunk, session->chat_buffer, snapshot_len - first_chunk);
  }
  buffer[snapshot_len] = '\0';
  *out_buffer = buffer;
  *out_length = snapshot_len;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_session_chat_clear_internal(
  shoots_session_t *session,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (session == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "session is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  shoots_error_code_t session_status =
      shoots_validate_session(session->engine, session, out_error);
  if (session_status != SHOOTS_OK) {
    return session_status;
  }
  if (session->chat_capacity > 0 && session->chat_buffer != NULL) {
    memset(session->chat_buffer, 0, session->chat_capacity);
  }
  session->chat_size = 0;
  session->chat_head = 0;
  shoots_assert_invariants(session->engine);
  return SHOOTS_OK;
}

shoots_error_code_t shoots_infer(shoots_engine_t *engine,
                                 const shoots_inference_request_t *request,
                                 shoots_inference_response_t *response,
                                 shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  if (request == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "request is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (response == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "response is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (request->input_tokens == NULL && request->input_token_count > 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "input_tokens is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  shoots_error_code_t runtime_status = shoots_provider_runtime_validate_ready(
      engine->provider_runtime, out_error);
  if (runtime_status != SHOOTS_OK) {
    return runtime_status;
  }
  shoots_error_code_t model_status =
      shoots_validate_model(engine, request->model, out_error);
  if (model_status != SHOOTS_OK) {
    return model_status;
  }
  shoots_error_set(out_error, SHOOTS_ERR_UNSUPPORTED, SHOOTS_SEVERITY_RECOVERABLE,
                   "NOT_IMPLEMENTED");
  return SHOOTS_ERR_UNSUPPORTED;
}

shoots_error_code_t shoots_embed(shoots_engine_t *engine,
                                 const shoots_embedding_request_t *request,
                                 shoots_embedding_response_t *response,
                                 shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  if (request == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "request is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (response == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "response is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (request->input_tokens == NULL && request->input_token_count > 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "input_tokens is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  shoots_error_code_t runtime_status = shoots_provider_runtime_validate_ready(
      engine->provider_runtime, out_error);
  if (runtime_status != SHOOTS_OK) {
    return runtime_status;
  }
  shoots_error_code_t model_status =
      shoots_validate_model(engine, request->model, out_error);
  if (model_status != SHOOTS_OK) {
    return model_status;
  }
  shoots_error_set(out_error, SHOOTS_ERR_UNSUPPORTED, SHOOTS_SEVERITY_RECOVERABLE,
                   "NOT_IMPLEMENTED");
  return SHOOTS_ERR_UNSUPPORTED;
}
