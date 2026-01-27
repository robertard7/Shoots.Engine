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
#define SHOOTS_LEDGER_MAX_ENTRIES 256u
#define SHOOTS_LEDGER_MAX_BYTES 16384u
#define SHOOTS_COMMAND_MAX_ENTRIES 256u
#define SHOOTS_COMMAND_MAX_BYTES 16384u
#define SHOOTS_RESULT_MAX_BYTES 4096u

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
      if (cursor->state == SHOOTS_SESSION_STATE_ACTIVE) {
        assert(cursor->next_execution_slot != 0);
        if (cursor->has_active_execution) {
          assert(cursor->active_execution_slot != 0);
          assert(cursor->active_execution_slot < cursor->next_execution_slot);
        }
      }
      cursor = cursor->next;
    }
  }
  if (engine->ledger_entry_count == 0) {
    assert(engine->ledger_head == NULL);
    assert(engine->ledger_tail == NULL);
    assert(engine->ledger_total_bytes == 0);
  } else {
    assert(engine->ledger_head != NULL);
    assert(engine->ledger_tail != NULL);
    assert(engine->ledger_tail->next == NULL);
    assert(engine->ledger_entry_count <= SHOOTS_LEDGER_MAX_ENTRIES);
    assert(engine->ledger_total_bytes <= SHOOTS_LEDGER_MAX_BYTES);
    shoots_ledger_entry_t *ledger_cursor = engine->ledger_head;
    uint64_t last_entry_id = 0;
    while (ledger_cursor != NULL) {
      assert(ledger_cursor->entry_id > last_entry_id);
      last_entry_id = ledger_cursor->entry_id;
      ledger_cursor = ledger_cursor->next;
    }
  }
  if (engine->commands_entry_count == 0) {
    assert(engine->commands_head == NULL);
    assert(engine->commands_tail == NULL);
    assert(engine->commands_total_bytes == 0);
  } else {
    assert(engine->commands_head != NULL);
    assert(engine->commands_tail != NULL);
    assert(engine->commands_tail->next == NULL);
    assert(engine->commands_entry_count <= SHOOTS_COMMAND_MAX_ENTRIES);
    assert(engine->commands_total_bytes <= SHOOTS_COMMAND_MAX_BYTES);
  }
  if (engine->intents_head == NULL) {
    assert(engine->intents_tail == NULL);
  } else {
    assert(engine->intents_tail != NULL);
    assert(engine->intents_tail->next == NULL);
    shoots_intent_record_t *intent_cursor = engine->intents_head;
    while (intent_cursor != NULL) {
      shoots_intent_record_t *check = intent_cursor->next;
      while (check != NULL) {
        assert(strcmp(intent_cursor->intent_id, check->intent_id) != 0);
        check = check->next;
      }
      intent_cursor = intent_cursor->next;
    }
  }
  if (engine->results_head == NULL) {
    assert(engine->results_tail == NULL);
  } else {
    assert(engine->results_tail != NULL);
    assert(engine->results_tail->next == NULL);
  }
  shoots_command_record_t *command_cursor = engine->commands_head;
  uint64_t last_command_seq = 0;
  while (command_cursor != NULL) {
    assert(command_cursor->command_seq != 0);
    assert(command_cursor->execution_slot != 0);
    assert(command_cursor->command_seq > last_command_seq);
    last_command_seq = command_cursor->command_seq;
    shoots_command_record_t *previous = engine->commands_head;
    uint64_t last_slot = 0;
    while (previous != command_cursor) {
      if (previous->session_id == command_cursor->session_id) {
        if (previous->execution_slot > last_slot) {
          last_slot = previous->execution_slot;
        }
      }
      previous = previous->next;
    }
    if (last_slot != 0) {
      assert(command_cursor->execution_slot > last_slot);
    }
    command_cursor = command_cursor->next;
  }
  shoots_result_record_t *result_cursor = engine->results_head;
  while (result_cursor != NULL) {
    assert(result_cursor->ledger_entry_id != 0);
    shoots_ledger_entry_t *ledger_cursor = engine->ledger_head;
    int found = 0;
    while (ledger_cursor != NULL) {
      if (ledger_cursor->entry_id == result_cursor->ledger_entry_id) {
        found = 1;
        assert(ledger_cursor->type == SHOOTS_LEDGER_ENTRY_RESULT);
        break;
      }
      ledger_cursor = ledger_cursor->next;
    }
    assert(found);
    shoots_result_record_t *check = result_cursor->next;
    while (check != NULL) {
      assert(check->ledger_entry_id != result_cursor->ledger_entry_id);
      check = check->next;
    }
    result_cursor = result_cursor->next;
  }
  shoots_ledger_entry_t *ledger_cursor = engine->ledger_head;
  while (ledger_cursor != NULL) {
    if (ledger_cursor->type == SHOOTS_LEDGER_ENTRY_RESULT) {
      shoots_result_record_t *result_check = engine->results_head;
      int found = 0;
      while (result_check != NULL) {
        if (result_check->ledger_entry_id == ledger_cursor->entry_id) {
          found = 1;
          break;
        }
        result_check = result_check->next;
      }
      assert(found);
    }
    ledger_cursor = ledger_cursor->next;
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

static void shoots_register_ledger_entry(shoots_engine_t *engine,
                                         shoots_ledger_entry_t *entry) {
  if (engine->ledger_tail == NULL) {
    engine->ledger_head = entry;
    engine->ledger_tail = entry;
    return;
  }
  engine->ledger_tail->next = entry;
  engine->ledger_tail = entry;
}

static void shoots_register_command(shoots_engine_t *engine, shoots_command_record_t *record) {
  if (engine->commands_tail == NULL) {
    engine->commands_head = record;
    engine->commands_tail = record;
    return;
  }
  engine->commands_tail->next = record;
  engine->commands_tail = record;
}

static void shoots_register_intent(shoots_engine_t *engine, shoots_intent_record_t *record) {
  if (engine->intents_tail == NULL) {
    engine->intents_head = record;
    engine->intents_tail = record;
    return;
  }
  engine->intents_tail->next = record;
  engine->intents_tail = record;
}

static void shoots_register_result(shoots_engine_t *engine, shoots_result_record_t *record) {
  if (engine->results_tail == NULL) {
    engine->results_head = record;
    engine->results_tail = record;
    return;
  }
  engine->results_tail->next = record;
  engine->results_tail = record;
}

static int shoots_intent_exists(shoots_engine_t *engine, const char *intent_id) {
  shoots_intent_record_t *cursor = engine->intents_head;
  while (cursor != NULL) {
    if (strcmp(cursor->intent_id, intent_id) == 0) {
      return 1;
    }
    cursor = cursor->next;
  }
  return 0;
}

static void shoots_session_set_last_error(shoots_session_t *session, const char *message) {
  if (session == NULL || session->engine == NULL) {
    return;
  }
  if (session->last_error != NULL) {
    shoots_engine_alloc_free_internal(session->engine, session->last_error);
    session->last_error = NULL;
  }
  if (message == NULL) {
    return;
  }
  size_t message_len = strlen(message);
  char *copy = (char *)shoots_engine_alloc_internal(
      session->engine, message_len + 1, NULL);
  if (copy == NULL) {
    return;
  }
  memcpy(copy, message, message_len + 1);
  session->last_error = copy;
}

static void shoots_emit_command_error(shoots_engine_t *engine,
                                      shoots_session_t *session,
                                      const char *message,
                                      const char *ledger_message) {
  if (engine == NULL || session == NULL) {
    return;
  }
  if (message != NULL) {
    shoots_session_set_last_error(session, message);
  }
  if (ledger_message != NULL && ledger_message[0] != '\0') {
    shoots_ledger_entry_t *error_entry = NULL;
    shoots_ledger_append_internal(engine, SHOOTS_LEDGER_ENTRY_ERROR,
                                  ledger_message, &error_entry, NULL);
  }
}

static void shoots_evict_result_by_ledger_id(shoots_engine_t *engine,
                                             uint64_t ledger_entry_id) {
  if (engine == NULL || ledger_entry_id == 0) {
    return;
  }
  shoots_result_record_t *prev = NULL;
  shoots_result_record_t *cursor = engine->results_head;
  while (cursor != NULL) {
    if (cursor->ledger_entry_id == ledger_entry_id) {
      if (prev == NULL) {
        engine->results_head = cursor->next;
      } else {
        prev->next = cursor->next;
      }
      if (engine->results_tail == cursor) {
        engine->results_tail = prev;
      }
      shoots_engine_alloc_free_internal(engine, cursor->command_id);
      shoots_engine_alloc_free_internal(engine, cursor->payload);
      cursor->command_id = NULL;
      cursor->payload = NULL;
      cursor->command_id_len = 0;
      cursor->payload_len = 0;
      shoots_engine_alloc_free_internal(engine, cursor);
      return;
    }
    prev = cursor;
    cursor = cursor->next;
  }
}

static void shoots_evict_ledger_head(shoots_engine_t *engine) {
  if (engine == NULL || engine->ledger_head == NULL) {
    return;
  }
  shoots_ledger_entry_t *entry = engine->ledger_head;
#ifndef NDEBUG
  if (entry->next != NULL) {
    assert(entry->next->entry_id > entry->entry_id);
  }
#endif
  engine->ledger_head = entry->next;
  if (engine->ledger_head == NULL) {
    engine->ledger_tail = NULL;
  }
  shoots_evict_result_by_ledger_id(engine, entry->entry_id);
  if (engine->ledger_entry_count > 0) {
    engine->ledger_entry_count--;
  }
  if (entry->payload_len <= engine->ledger_total_bytes) {
    engine->ledger_total_bytes -= entry->payload_len;
  } else {
    engine->ledger_total_bytes = 0;
  }
  shoots_engine_alloc_free_internal(engine, entry->payload);
  entry->payload = NULL;
  entry->payload_len = 0;
  shoots_engine_alloc_free_internal(engine, entry);
}

static void shoots_evict_command_head(shoots_engine_t *engine) {
  if (engine == NULL || engine->commands_head == NULL) {
    return;
  }
  shoots_command_record_t *record = engine->commands_head;
#ifndef NDEBUG
  if (record->next != NULL) {
    assert(record->next->command_seq > record->command_seq);
  }
#endif
  engine->commands_head = record->next;
  if (engine->commands_head == NULL) {
    engine->commands_tail = NULL;
  }
  if (engine->commands_entry_count > 0) {
    engine->commands_entry_count--;
  }
  size_t record_bytes = record->command_id_len + record->args_len;
  if (record_bytes <= engine->commands_total_bytes) {
    engine->commands_total_bytes -= record_bytes;
  } else {
    engine->commands_total_bytes = 0;
  }
  shoots_engine_alloc_free_internal(engine, record->command_id);
  shoots_engine_alloc_free_internal(engine, record->args);
  record->command_id = NULL;
  record->args = NULL;
  record->command_id_len = 0;
  record->args_len = 0;
  shoots_engine_alloc_free_internal(engine, record);
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
  engine->intents_head = NULL;
  engine->intents_tail = NULL;
  engine->next_intent_created_at = 1;
  engine->ledger_head = NULL;
  engine->ledger_tail = NULL;
  engine->ledger_entry_count = 0;
  engine->ledger_total_bytes = 0;
  engine->next_ledger_id = 1;
  engine->results_head = NULL;
  engine->results_tail = NULL;
  engine->commands_head = NULL;
  engine->commands_tail = NULL;
  engine->commands_entry_count = 0;
  engine->commands_total_bytes = 0;
  engine->next_command_seq = 1;

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
  engine->ledger_head = NULL;
  engine->ledger_tail = NULL;
  engine->ledger_entry_count = 0;
  engine->ledger_total_bytes = 0;
  engine->next_ledger_id = 0;
  engine->intents_head = NULL;
  engine->intents_tail = NULL;
  engine->next_intent_created_at = 0;
  engine->results_head = NULL;
  engine->results_tail = NULL;
  engine->commands_head = NULL;
  engine->commands_tail = NULL;
  engine->commands_entry_count = 0;
  engine->commands_total_bytes = 0;
  engine->next_command_seq = 0;
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
  if (engine->next_intent_created_at == 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "intent sequence exhausted");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (shoots_intent_exists(engine, intent_id)) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "intent_id already exists");
    return SHOOTS_ERR_INVALID_ARGUMENT;
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
  session->next_execution_slot = 1;

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
  session->active_execution_slot = 0;
  session->has_active_execution = 0;
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

  shoots_intent_record_t *intent_record =
      (shoots_intent_record_t *)shoots_engine_alloc_internal(
          engine, sizeof(*intent_record), out_error);
  if (intent_record == NULL) {
    session->magic = SHOOTS_SESSION_MAGIC_DESTROYED;
    shoots_engine_alloc_free_internal(engine, session->chat_buffer);
    session->chat_buffer = NULL;
    shoots_engine_alloc_free_internal(engine, session->intent_id);
    session->intent_id = NULL;
    shoots_engine_alloc_free_internal(engine, session);
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memset(intent_record, 0, sizeof(*intent_record));
  intent_record->created_at = engine->next_intent_created_at;
  intent_record->session_id = session->session_id;
  intent_record->intent_id_len = intent_len;
  intent_record->intent_id = session->intent_id;
  intent_record->next = NULL;
  if (engine->next_intent_created_at == UINT64_MAX) {
    engine->next_intent_created_at = 0;
  } else {
    engine->next_intent_created_at++;
  }
  shoots_register_intent(engine, intent_record);

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

shoots_error_code_t shoots_ledger_append_internal(
  shoots_engine_t *engine,
  shoots_ledger_entry_type_t type,
  const char *payload,
  shoots_ledger_entry_t **out_entry,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_entry == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "out_entry is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_entry = NULL;
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  if (payload == NULL || payload[0] == '\0') {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "payload is null or empty");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (type < SHOOTS_LEDGER_ENTRY_DECISION || type > SHOOTS_LEDGER_ENTRY_ERROR) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger entry type invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (engine->next_ledger_id == 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger id exhausted");
    return SHOOTS_ERR_INVALID_STATE;
  }
  size_t payload_len = strlen(payload);
  if (payload_len > SHOOTS_LEDGER_MAX_BYTES) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "payload too large");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }

  while (engine->ledger_entry_count >= SHOOTS_LEDGER_MAX_ENTRIES ||
         engine->ledger_total_bytes + payload_len > SHOOTS_LEDGER_MAX_BYTES) {
    shoots_evict_ledger_head(engine);
  }

  shoots_ledger_entry_t *entry = (shoots_ledger_entry_t *)shoots_engine_alloc_internal(
      engine, sizeof(*entry), out_error);
  if (entry == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memset(entry, 0, sizeof(*entry));
  entry->entry_id = engine->next_ledger_id;
  entry->type = type;
  entry->payload_len = payload_len;
  entry->next = NULL;
  if (engine->next_ledger_id == UINT64_MAX) {
    engine->next_ledger_id = 0;
  } else {
    engine->next_ledger_id++;
  }

  char *payload_copy = (char *)shoots_engine_alloc_internal(
      engine, payload_len + 1, out_error);
  if (payload_copy == NULL) {
    shoots_engine_alloc_free_internal(engine, entry);
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memcpy(payload_copy, payload, payload_len + 1);
  entry->payload = payload_copy;

  shoots_register_ledger_entry(engine, entry);
  engine->ledger_entry_count++;
  engine->ledger_total_bytes += payload_len;
  shoots_assert_invariants(engine);
  *out_entry = entry;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_ledger_query_type_internal(
  shoots_engine_t *engine,
  shoots_ledger_entry_type_t type,
  shoots_ledger_entry_t ***out_entries,
  size_t *out_count,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_entries == NULL || out_count == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "output is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_entries = NULL;
  *out_count = 0;
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  if (type < SHOOTS_LEDGER_ENTRY_DECISION || type > SHOOTS_LEDGER_ENTRY_ERROR) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger entry type invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  size_t match_count = 0;
  shoots_ledger_entry_t *cursor = engine->ledger_head;
  while (cursor != NULL) {
    if (cursor->type == type) {
      match_count++;
    }
    cursor = cursor->next;
  }
  if (match_count == 0) {
    return SHOOTS_OK;
  }
  if (match_count > SIZE_MAX / sizeof(shoots_ledger_entry_t *)) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "result size overflow");
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  shoots_ledger_entry_t **entries =
      (shoots_ledger_entry_t **)shoots_engine_alloc_internal(
          engine, match_count * sizeof(*entries), out_error);
  if (entries == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  size_t index = 0;
  cursor = engine->ledger_head;
  while (cursor != NULL) {
    if (cursor->type == type) {
      entries[index++] = cursor;
    }
    cursor = cursor->next;
  }
  *out_entries = entries;
  *out_count = match_count;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_ledger_query_substring_internal(
  shoots_engine_t *engine,
  const char *substring,
  shoots_ledger_entry_t ***out_entries,
  size_t *out_count,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_entries == NULL || out_count == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "output is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_entries = NULL;
  *out_count = 0;
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  if (substring == NULL || substring[0] == '\0') {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "substring is null or empty");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  size_t match_count = 0;
  shoots_ledger_entry_t *cursor = engine->ledger_head;
  while (cursor != NULL) {
    if (strstr(cursor->payload, substring) != NULL) {
      match_count++;
    }
    cursor = cursor->next;
  }
  if (match_count == 0) {
    return SHOOTS_OK;
  }
  if (match_count > SIZE_MAX / sizeof(shoots_ledger_entry_t *)) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "result size overflow");
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  shoots_ledger_entry_t **entries =
      (shoots_ledger_entry_t **)shoots_engine_alloc_internal(
          engine, match_count * sizeof(*entries), out_error);
  if (entries == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  size_t index = 0;
  cursor = engine->ledger_head;
  while (cursor != NULL) {
    if (strstr(cursor->payload, substring) != NULL) {
      entries[index++] = cursor;
    }
    cursor = cursor->next;
  }
  *out_entries = entries;
  *out_count = match_count;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_command_append_internal(
  shoots_engine_t *engine,
  shoots_session_t *session,
  uint64_t execution_slot,
  const char *command_id,
  const char *args,
  uint8_t has_last_result,
  int32_t last_result_code,
  shoots_command_record_t **out_record,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_record == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "out_record is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_record = NULL;
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
    shoots_emit_command_error(engine, session, "session not active",
                              "command failure: session not active");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (!shoots_intent_exists(engine, session->intent_id)) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "intent record missing");
    shoots_emit_command_error(engine, session, "intent record missing",
                              "command failure: intent missing");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (session->has_active_execution) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "session execution already active");
    shoots_emit_command_error(engine, session, "session execution already active",
                              "command failure: execution already active");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (execution_slot == 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "execution_slot is invalid");
    shoots_emit_command_error(engine, session, "execution_slot is invalid",
                              "command failure: execution_slot invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (command_id == NULL || command_id[0] == '\0') {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "command_id is null or empty");
    shoots_emit_command_error(engine, session, "command_id is null or empty",
                              "command failure: command_id invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (args == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "args is null");
    shoots_emit_command_error(engine, session, "args is null",
                              "command failure: args invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (has_last_result > 1) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "has_last_result invalid");
    shoots_emit_command_error(engine, session, "has_last_result invalid",
                              "command failure: has_last_result invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (engine->next_command_seq == 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "command sequence exhausted");
    shoots_emit_command_error(engine, session, "command sequence exhausted",
                              "command failure: command sequence exhausted");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (session->next_execution_slot == 0) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "execution slots exhausted");
    shoots_emit_command_error(engine, session, "execution slots exhausted",
                              "command failure: execution slots exhausted");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (execution_slot != session->next_execution_slot) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "execution slot out of order");
    shoots_emit_command_error(engine, session, "execution slot out of order",
                              "command failure: execution slot out of order");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  size_t command_id_len = strlen(command_id);
  size_t args_len = strlen(args);
  size_t record_bytes = command_id_len + args_len;
  if (record_bytes > SHOOTS_COMMAND_MAX_BYTES) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "command payload too large");
    shoots_emit_command_error(engine, session, "command payload too large",
                              "command failure: payload too large");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }

  while (engine->commands_entry_count >= SHOOTS_COMMAND_MAX_ENTRIES ||
         engine->commands_total_bytes + record_bytes > SHOOTS_COMMAND_MAX_BYTES) {
    shoots_evict_command_head(engine);
  }

  shoots_command_record_t *record =
      (shoots_command_record_t *)shoots_engine_alloc_internal(
          engine, sizeof(*record), out_error);
  if (record == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memset(record, 0, sizeof(*record));
  record->command_seq = engine->next_command_seq;
  record->session_id = session->session_id;
  record->execution_slot = execution_slot;
  record->has_last_result = has_last_result;
  record->last_result_code = last_result_code;
  record->command_id_len = command_id_len;
  record->args_len = args_len;
  record->next = NULL;
  if (engine->next_command_seq == UINT64_MAX) {
    engine->next_command_seq = 0;
  } else {
    engine->next_command_seq++;
  }
  if (session->next_execution_slot == UINT64_MAX) {
    session->next_execution_slot = 0;
  } else {
    session->next_execution_slot++;
  }
  session->has_active_execution = 1;
  session->active_execution_slot = execution_slot;

  char *command_id_copy = (char *)shoots_engine_alloc_internal(
      engine, command_id_len + 1, out_error);
  if (command_id_copy == NULL) {
    shoots_engine_alloc_free_internal(engine, record);
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memcpy(command_id_copy, command_id, command_id_len + 1);
  record->command_id = command_id_copy;

  char *args_copy = (char *)shoots_engine_alloc_internal(
      engine, args_len + 1, out_error);
  if (args_copy == NULL) {
    shoots_engine_alloc_free_internal(engine, record->command_id);
    record->command_id = NULL;
    shoots_engine_alloc_free_internal(engine, record);
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memcpy(args_copy, args, args_len + 1);
  record->args = args_copy;

  shoots_register_command(engine, record);
  engine->commands_entry_count++;
  engine->commands_total_bytes += record_bytes;
  shoots_assert_invariants(engine);
  *out_record = record;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_result_append_internal(
  shoots_engine_t *engine,
  shoots_session_t *session,
  const char *command_id,
  shoots_result_status_t status,
  const char *payload,
  shoots_result_record_t **out_record,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_record == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "out_record is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_record = NULL;
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
    shoots_emit_command_error(engine, session, "session not active",
                              "result failure: session not active");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (!shoots_intent_exists(engine, session->intent_id)) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "intent record missing");
    shoots_emit_command_error(engine, session, "intent record missing",
                              "result failure: intent missing");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (!session->has_active_execution) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_STATE, SHOOTS_SEVERITY_RECOVERABLE,
                     "session execution not active");
    shoots_emit_command_error(engine, session, "session execution not active",
                              "result failure: execution not active");
    return SHOOTS_ERR_INVALID_STATE;
  }
  if (command_id == NULL || command_id[0] == '\0') {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "command_id is null or empty");
    shoots_emit_command_error(engine, session, "command_id is null or empty",
                              "result failure: command_id invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (payload == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "payload is null");
    shoots_emit_command_error(engine, session, "payload is null",
                              "result failure: payload invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (status < SHOOTS_RESULT_STATUS_OK || status > SHOOTS_RESULT_STATUS_ERROR) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "result status invalid");
    shoots_emit_command_error(engine, session, "result status invalid",
                              "result failure: status invalid");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  size_t command_id_len = strlen(command_id);
  size_t payload_len = strlen(payload);
  if (payload_len > SHOOTS_RESULT_MAX_BYTES) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "payload too large");
    shoots_emit_command_error(engine, session, "payload too large",
                              "result failure: payload too large");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  if (command_id_len > SIZE_MAX - payload_len) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "payload size overflow");
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  const char *status_text =
      status == SHOOTS_RESULT_STATUS_OK ? "OK" : "ERROR";
  size_t ledger_len = strlen("command_id=") + command_id_len +
                      strlen(" status=") + strlen(status_text) +
                      strlen(" payload=") + payload_len;
  if (ledger_len > SHOOTS_LEDGER_MAX_BYTES) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "ledger payload too large");
    shoots_emit_command_error(engine, session, "ledger payload too large",
                              "result failure: ledger payload too large");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  char *ledger_payload = (char *)shoots_engine_alloc_internal(
      engine, ledger_len + 1, out_error);
  if (ledger_payload == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memcpy(ledger_payload, "command_id=", strlen("command_id="));
  size_t offset = strlen("command_id=");
  memcpy(ledger_payload + offset, command_id, command_id_len);
  offset += command_id_len;
  memcpy(ledger_payload + offset, " status=", strlen(" status="));
  offset += strlen(" status=");
  memcpy(ledger_payload + offset, status_text, strlen(status_text));
  offset += strlen(status_text);
  memcpy(ledger_payload + offset, " payload=", strlen(" payload="));
  offset += strlen(" payload=");
  memcpy(ledger_payload + offset, payload, payload_len);
  offset += payload_len;
  ledger_payload[offset] = '\0';

  shoots_ledger_entry_t *ledger_entry = NULL;
  shoots_error_code_t ledger_status = shoots_ledger_append_internal(
      engine, SHOOTS_LEDGER_ENTRY_RESULT, ledger_payload, &ledger_entry, out_error);
  shoots_engine_alloc_free_internal(engine, ledger_payload);
  if (ledger_status != SHOOTS_OK) {
    shoots_emit_command_error(engine, session, "ledger append failed",
                              "result failure: ledger append failed");
    return ledger_status;
  }

  shoots_result_record_t *record =
      (shoots_result_record_t *)shoots_engine_alloc_internal(
          engine, sizeof(*record), out_error);
  if (record == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memset(record, 0, sizeof(*record));
  record->ledger_entry_id = ledger_entry->entry_id;
  record->status = status;
  record->command_id_len = command_id_len;
  record->payload_len = payload_len;
  record->next = NULL;
  char *command_id_copy = (char *)shoots_engine_alloc_internal(
      engine, command_id_len + 1, out_error);
  if (command_id_copy == NULL) {
    shoots_engine_alloc_free_internal(engine, record);
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memcpy(command_id_copy, command_id, command_id_len + 1);
  record->command_id = command_id_copy;
  char *payload_copy = (char *)shoots_engine_alloc_internal(
      engine, payload_len + 1, out_error);
  if (payload_copy == NULL) {
    shoots_engine_alloc_free_internal(engine, record->command_id);
    record->command_id = NULL;
    shoots_engine_alloc_free_internal(engine, record);
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  memcpy(payload_copy, payload, payload_len + 1);
  record->payload = payload_copy;
  shoots_register_result(engine, record);
  if (status == SHOOTS_RESULT_STATUS_ERROR) {
    shoots_session_set_last_error(session, payload);
    shoots_ledger_entry_t *error_entry = NULL;
    shoots_ledger_append_internal(engine, SHOOTS_LEDGER_ENTRY_ERROR,
                                  "command failure: result error",
                                  &error_entry, NULL);
  }
  session->has_active_execution = 0;
  session->active_execution_slot = 0;
  shoots_assert_invariants(engine);
  *out_record = record;
  return SHOOTS_OK;
}

shoots_error_code_t shoots_command_fetch_last_internal(
  shoots_engine_t *engine,
  size_t max_count,
  shoots_command_record_t ***out_records,
  size_t *out_count,
  shoots_error_info_t *out_error) {
  shoots_error_clear(out_error);
  if (out_records == NULL || out_count == NULL) {
    shoots_error_set(out_error, SHOOTS_ERR_INVALID_ARGUMENT, SHOOTS_SEVERITY_RECOVERABLE,
                     "output is null");
    return SHOOTS_ERR_INVALID_ARGUMENT;
  }
  *out_records = NULL;
  *out_count = 0;
  shoots_error_code_t engine_status = shoots_validate_engine(engine, out_error);
  if (engine_status != SHOOTS_OK) {
    return engine_status;
  }
  if (max_count == 0) {
    return SHOOTS_OK;
  }
  size_t total = 0;
  shoots_command_record_t *cursor = engine->commands_head;
  while (cursor != NULL) {
    total++;
    cursor = cursor->next;
  }
  if (total == 0) {
    return SHOOTS_OK;
  }
  size_t slice_count = total;
  if (slice_count > max_count) {
    slice_count = max_count;
  }
  if (slice_count > SIZE_MAX / sizeof(shoots_command_record_t *)) {
    shoots_error_set(out_error, SHOOTS_ERR_OUT_OF_MEMORY, SHOOTS_SEVERITY_RECOVERABLE,
                     "result size overflow");
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  shoots_command_record_t **records =
      (shoots_command_record_t **)shoots_engine_alloc_internal(
          engine, slice_count * sizeof(*records), out_error);
  if (records == NULL) {
    return SHOOTS_ERR_OUT_OF_MEMORY;
  }
  size_t skip = total - slice_count;
  cursor = engine->commands_head;
  while (cursor != NULL && skip > 0) {
    cursor = cursor->next;
    skip--;
  }
  size_t index = 0;
  while (cursor != NULL && index < slice_count) {
    records[index++] = cursor;
    cursor = cursor->next;
  }
  *out_records = records;
  *out_count = slice_count;
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
