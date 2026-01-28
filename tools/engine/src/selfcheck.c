#include "engine_internal.h"

#ifndef NDEBUG
#include <assert.h>
#include <string.h>
#endif

static uint64_t selfcheck_hash_tool_descriptor(
  const char *tool_id,
  shoots_tool_category_t category,
  uint32_t version,
  uint64_t capabilities,
  const shoots_tool_constraints_t *constraints,
  uint32_t determinism_flags) {
  uint64_t hash = 14695981039346656037ull;
  uint32_t max_args = 0;
  uint32_t max_bytes = 0;
  shoots_tool_confirm_policy_t confirm_policy = SHOOTS_TOOL_CONFIRM_NONE;
  const unsigned char *cursor = (const unsigned char *)tool_id;
  while (*cursor != '\0') {
    hash ^= (uint64_t)(*cursor);
    hash *= 1099511628211ull;
    cursor++;
  }
  for (size_t index = 0; index < sizeof(category); index++) {
    hash ^= (uint64_t)((category >> (index * 8)) & 0xffu);
    hash *= 1099511628211ull;
  }
  for (size_t index = 0; index < sizeof(version); index++) {
    hash ^= (uint64_t)((version >> (index * 8)) & 0xffu);
    hash *= 1099511628211ull;
  }
  for (size_t index = 0; index < sizeof(capabilities); index++) {
    hash ^= (uint64_t)((capabilities >> (index * 8)) & 0xffu);
    hash *= 1099511628211ull;
  }
  if (constraints != NULL) {
    max_args = constraints->max_args;
    max_bytes = constraints->max_bytes;
    confirm_policy = constraints->confirm_policy;
  }
  for (size_t index = 0; index < sizeof(max_args); index++) {
    hash ^= (uint64_t)((max_args >> (index * 8)) & 0xffu);
    hash *= 1099511628211ull;
  }
  for (size_t index = 0; index < sizeof(max_bytes); index++) {
    hash ^= (uint64_t)((max_bytes >> (index * 8)) & 0xffu);
    hash *= 1099511628211ull;
  }
  for (size_t index = 0; index < sizeof(confirm_policy); index++) {
    hash ^= (uint64_t)((confirm_policy >> (index * 8)) & 0xffu);
    hash *= 1099511628211ull;
  }
  for (size_t index = 0; index < sizeof(determinism_flags); index++) {
    hash ^= (uint64_t)((determinism_flags >> (index * 8)) & 0xffu);
    hash *= 1099511628211ull;
  }
  return hash;
}

static int selfcheck_reason_code_valid(const char *code_text) {
  return strcmp(code_text, "OK") == 0 ||
         strcmp(code_text, "TOOL_NOT_FOUND") == 0 ||
         strcmp(code_text, "CONSTRAINT_MISMATCH") == 0 ||
         strcmp(code_text, "CAPABILITY_MISMATCH") == 0 ||
         strcmp(code_text, "INVALID_DESCRIPTOR") == 0;
}

void selfcheck_run(shoots_engine_t *engine) {
#ifndef NDEBUG
  if (engine == NULL) {
    return;
  }

  shoots_tool_record_t *tool_cursor = engine->tools_head;
  while (tool_cursor != NULL) {
    assert(tool_cursor->tool_id != NULL);
    assert(tool_cursor->tool_id_len >= SHOOTS_TOOL_ID_MIN_LEN);
    assert(tool_cursor->tool_id_len <= SHOOTS_TOOL_ID_MAX_LEN);
    assert(strlen(tool_cursor->tool_id) == tool_cursor->tool_id_len);
    assert(tool_cursor->version >= SHOOTS_TOOL_VERSION_MIN);
    assert(tool_cursor->version <= SHOOTS_TOOL_VERSION_MAX);
    assert((tool_cursor->determinism_flags & ~SHOOTS_TOOL_DETERMINISM_MASK) == 0u);
    assert((tool_cursor->capabilities & ~SHOOTS_TOOL_CAPABILITIES_ALLOWED) == 0u);
    assert(tool_cursor->constraints.max_args <= SHOOTS_TOOL_MAX_ARGS);
    assert(tool_cursor->constraints.max_bytes <= SHOOTS_TOOL_MAX_BYTES);
    assert(tool_cursor->constraints.confirm_policy >= SHOOTS_TOOL_CONFIRM_NONE);
    assert(tool_cursor->constraints.confirm_policy <= SHOOTS_TOOL_CONFIRM_ON_FAIL);
    if (engine->tools_locked) {
      uint64_t expected_hash = selfcheck_hash_tool_descriptor(
          tool_cursor->tool_id, tool_cursor->category, tool_cursor->version,
          tool_cursor->capabilities, &tool_cursor->constraints,
          tool_cursor->determinism_flags);
      assert(tool_cursor->tool_hash == expected_hash);
    }
    shoots_tool_record_t *tool_check = tool_cursor->next;
    while (tool_check != NULL) {
      assert(strcmp(tool_cursor->tool_id, tool_check->tool_id) != 0);
      tool_check = tool_check->next;
    }
    tool_cursor = tool_cursor->next;
  }

  shoots_ledger_entry_t *ledger_check = engine->ledger_head;
  while (ledger_check != NULL) {
    if (ledger_check->type == SHOOTS_LEDGER_ENTRY_DECISION &&
        strncmp(ledger_check->payload, "plan intent_id=", strlen("plan intent_id=")) == 0) {
      const char *cursor = ledger_check->payload;
      while ((cursor = strstr(cursor, "code=")) != NULL) {
        cursor += strlen("code=");
        const char *code_end = strchr(cursor, ' ');
        size_t code_len = code_end != NULL ? (size_t)(code_end - cursor) : strlen(cursor);
        char code_buf[32];
        if (code_len >= sizeof(code_buf)) {
          code_len = sizeof(code_buf) - 1;
        }
        memcpy(code_buf, cursor, code_len);
        code_buf[code_len] = '\0';
        assert(selfcheck_reason_code_valid(code_buf));
        const char *token = strstr(cursor, " token=");
        if (token != NULL) {
          token += strlen(" token=");
          const char *token_end = strchr(token, ' ');
          size_t token_len = token_end != NULL ? (size_t)(token_end - token) : strlen(token);
          assert(token_len < SHOOTS_TOOL_REASON_TOKEN_MAX);
        }
        cursor = cursor + code_len;
      }
    }
    ledger_check = ledger_check->next;
  }
  shoots_session_t *session = engine->sessions_head;
  while (session != NULL) {
    if (session->has_terminal_execution) {
      assert(session->terminal_execution_slot != 0);
      assert(session->terminal_execution_slot < session->next_execution_slot);
    }
    if (session->has_active_execution) {
      assert(session->active_execution_slot != 0);
      assert(session->active_execution_slot < session->next_execution_slot);
      if (session->has_terminal_execution) {
        assert(session->active_execution_slot > session->terminal_execution_slot);
      }
    }
    session = session->next;
  }

  shoots_command_record_t *command = engine->commands_head;
  while (command != NULL) {
    shoots_result_record_t *result_match = engine->results_head;
    int result_found = 0;
    while (result_match != NULL) {
      if (result_match->session_id == command->session_id &&
          result_match->execution_slot == command->execution_slot) {
        result_found = 1;
        break;
      }
      result_match = result_match->next;
    }
    shoots_session_t *session_match = engine->sessions_head;
    while (session_match != NULL &&
           session_match->session_id != command->session_id) {
      session_match = session_match->next;
    }
    if (session_match != NULL && session_match->has_active_execution &&
        session_match->active_execution_slot == command->execution_slot) {
      assert(!result_found);
    } else {
      assert(result_found);
    }
    command = command->next;
  }

  shoots_result_record_t *result = engine->results_head;
  while (result != NULL) {
    assert(result->ledger_entry_id != 0);
    assert(result->session_id != 0);
    assert(result->execution_slot != 0);
    shoots_ledger_entry_t *ledger = engine->ledger_head;
    int ledger_found = 0;
    while (ledger != NULL) {
      if (ledger->entry_id == result->ledger_entry_id) {
        ledger_found = 1;
        assert(ledger->type == SHOOTS_LEDGER_ENTRY_RESULT);
        break;
      }
      ledger = ledger->next;
    }
    assert(ledger_found);
    shoots_command_record_t *command = engine->commands_head;
    int command_found = 0;
    while (command != NULL) {
      if (command->session_id == result->session_id &&
          command->execution_slot == result->execution_slot &&
          command->command_id != NULL &&
          result->command_id != NULL &&
          strcmp(command->command_id, result->command_id) == 0) {
        command_found = 1;
        break;
      }
      command = command->next;
    }
    assert(command_found);
    shoots_result_record_t *check = result->next;
    while (check != NULL) {
      if (check->session_id == result->session_id) {
        assert(check->execution_slot != result->execution_slot);
      }
      assert(check->ledger_entry_id != result->ledger_entry_id);
      check = check->next;
    }
    result = result->next;
  }

  shoots_ledger_entry_t *ledger = engine->ledger_head;
  while (ledger != NULL) {
    if (ledger->type == SHOOTS_LEDGER_ENTRY_RESULT) {
      shoots_result_record_t *result_check = engine->results_head;
      int found = 0;
      while (result_check != NULL) {
        if (result_check->ledger_entry_id == ledger->entry_id) {
          found = 1;
          break;
        }
        result_check = result_check->next;
      }
      assert(found);
    }
    ledger = ledger->next;
  }
#else
  (void)engine;
#endif
}
