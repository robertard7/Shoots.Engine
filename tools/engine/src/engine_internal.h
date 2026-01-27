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

typedef enum shoots_ledger_entry_type {
  SHOOTS_LEDGER_ENTRY_DECISION = 0,
  SHOOTS_LEDGER_ENTRY_CONSTRAINT = 1,
  SHOOTS_LEDGER_ENTRY_COMMAND = 2,
  SHOOTS_LEDGER_ENTRY_RESULT = 3,
  SHOOTS_LEDGER_ENTRY_ERROR = 4
} shoots_ledger_entry_type_t;

typedef struct shoots_command_record {
  uint64_t command_seq;
  char *command_id;
  size_t command_id_len;
  char *args;
  size_t args_len;
  uint8_t has_last_result;
  int32_t last_result_code;
  struct shoots_command_record *next;
} shoots_command_record_t;

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

struct shoots_ledger_entry {
  uint64_t entry_id;
  shoots_ledger_entry_type_t type;
  char *payload;
  size_t payload_len;
  struct shoots_ledger_entry *next;
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
  struct shoots_ledger_entry *ledger_head;
  struct shoots_ledger_entry *ledger_tail;
  size_t ledger_entry_count;
  size_t ledger_total_bytes;
  uint64_t next_ledger_id;
  shoots_command_record_t *commands_head;
  shoots_command_record_t *commands_tail;
  size_t commands_entry_count;
  size_t commands_total_bytes;
  uint64_t next_command_seq;
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

shoots_error_code_t shoots_ledger_append_internal(
  shoots_engine_t *engine,
  shoots_ledger_entry_type_t type,
  const char *payload,
  struct shoots_ledger_entry **out_entry,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_ledger_query_type_internal(
  shoots_engine_t *engine,
  shoots_ledger_entry_type_t type,
  struct shoots_ledger_entry ***out_entries,
  size_t *out_count,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_ledger_query_substring_internal(
  shoots_engine_t *engine,
  const char *substring,
  struct shoots_ledger_entry ***out_entries,
  size_t *out_count,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_command_append_internal(
  shoots_engine_t *engine,
  const char *command_id,
  const char *args,
  uint8_t has_last_result,
  int32_t last_result_code,
  shoots_command_record_t **out_record,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_command_fetch_last_internal(
  shoots_engine_t *engine,
  size_t max_count,
  shoots_command_record_t ***out_records,
  size_t *out_count,
  shoots_error_info_t *out_error);

#endif
