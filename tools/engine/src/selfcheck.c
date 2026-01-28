#include "engine_internal.h"

#ifndef NDEBUG
#include <assert.h>
#include <string.h>
#endif

void selfcheck_run(shoots_engine_t *engine) {
#ifndef NDEBUG
  if (engine == NULL) {
    return;
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
