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

typedef enum shoots_session_state {
  SHOOTS_SESSION_STATE_UNINITIALIZED = 0,
  SHOOTS_SESSION_STATE_ACTIVE = 1,
  SHOOTS_SESSION_STATE_CLOSED = 2,
  SHOOTS_SESSION_STATE_DESTROYED = 3
} shoots_session_state_t;

typedef enum shoots_session_mode {
  SHOOTS_SESSION_MODE_UNSPECIFIED = 0,
  SHOOTS_SESSION_MODE_CONTINUATION = 1,
  SHOOTS_SESSION_MODE_TRANSACTIONAL = 2
} shoots_session_mode_t;

struct shoots_model {
  uint32_t magic;
  shoots_engine_t *engine;
  shoots_model_state_t state;
  struct shoots_model *next;
};

struct shoots_session {
  uint32_t magic;
  uint64_t session_id;
  shoots_engine_t *engine;
  shoots_session_state_t state;
  shoots_session_mode_t mode;
  char *intent_id;
  char *last_error;
  char *chat_buffer;
  size_t chat_capacity;
  size_t chat_size;
  size_t chat_head;
  struct shoots_session *next;
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
  struct shoots_session *sessions_head;
  struct shoots_session *sessions_tail;
  uint64_t next_session_id;
  shoots_engine_state_t state;
  uint32_t magic;
};

void *shoots_engine_alloc_internal(shoots_engine_t *engine,
                                   size_t bytes,
                                   shoots_error_info_t *out_error);

void shoots_engine_alloc_free_internal(shoots_engine_t *engine, void *buffer);

shoots_error_code_t shoots_session_create_internal(
  shoots_engine_t *engine,
  const char *intent_id,
  shoots_session_mode_t mode,
  struct shoots_session **out_session,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_attach_internal(
  shoots_engine_t *engine,
  uint64_t session_id,
  struct shoots_session **out_session,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_close_internal(
  shoots_engine_t *engine,
  struct shoots_session *session,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_chat_append_internal(
  struct shoots_session *session,
  const char *text,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_chat_snapshot_internal(
  struct shoots_session *session,
  char **out_buffer,
  size_t *out_length,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_chat_clear_internal(
  struct shoots_session *session,
  shoots_error_info_t *out_error);

#endif
