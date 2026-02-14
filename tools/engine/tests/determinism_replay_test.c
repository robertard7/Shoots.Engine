#include "engine_internal.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void must_ok(shoots_error_code_t code, const char *step, shoots_error_info_t *error) {
  if (code == SHOOTS_OK) {
    return;
  }
  fprintf(stderr, "%s failed: code=%d message=%s\n", step, (int)code,
          (error != NULL && error->message != NULL) ? error->message : "(none)");
  assert(0 && "determinism step failed");
}

static shoots_engine_t *create_engine_or_die(void) {
  shoots_config_t config;
  memset(&config, 0, sizeof(config));
  config.model_root_path = ".";
  config.max_memory_bytes = 1024u * 1024u;
  config.max_execution_steps = 1024u;
  shoots_engine_t *engine = NULL;
  shoots_error_info_t error;
  must_ok(shoots_engine_create(&config, &engine, &error), "shoots_engine_create", &error);
  return engine;
}

static void run_single_roundtrip(shoots_engine_t *engine) {
  shoots_error_info_t error;
  shoots_provider_descriptor_t provider;
  memset(&provider, 0, sizeof(provider));
  provider.provider_id_len = 5;
  memcpy(provider.provider_id, "provA", provider.provider_id_len + 1);
  provider.supported_tool_categories = SHOOTS_PROVIDER_TOOL_CATEGORY_EXECUTION;
  provider.max_concurrency = 8;
  provider.guarantees_mask = SHOOTS_PROVIDER_GUARANTEE_DETERMINISTIC;
  must_ok(shoots_provider_register_internal(engine, &provider, &error), "register provider", &error);

  engine->tools_locked = 0;
  shoots_tool_constraints_t constraints = {8, 64, SHOOTS_TOOL_CONFIRM_NONE};
  shoots_tool_record_t *record = NULL;
  must_ok(shoots_tool_register_internal(engine,
                                        "tool.exec",
                                        SHOOTS_TOOL_CATEGORY_EXECUTION,
                                        1,
                                        0x3u,
                                        &constraints,
                                        SHOOTS_TOOL_DETERMINISM_DETERMINISTIC,
                                        &record,
                                        &error),
          "register tool", &error);
  engine->tools_locked = 1;
  must_ok(shoots_provider_registry_lock_internal(engine, &error), "lock providers", &error);

  shoots_session_t *session = NULL;
  must_ok(shoots_session_create_internal(engine,
                                         "intent-deterministic",
                                         SHOOTS_SESSION_MODE_TRANSACTIONAL,
                                         &session,
                                         &error),
          "create session", &error);

  const char *tool_ids[1] = {"tool.exec"};
  shoots_tool_reject_reason_t reasons[1];
  memset(reasons, 0, sizeof(reasons));
  reasons[0].code = SHOOTS_TOOL_REJECT_OK;
  memcpy(reasons[0].token, "ok", 3);
  must_ok(shoots_session_plan_store_internal(session, 1, 0x424242ULL, tool_ids, reasons, 1, &error),
          "plan store", &error);

  shoots_provider_request_t request;
  memset(&request, 0, sizeof(request));
  const uint8_t arg_blob[] = {0x41, 0x42, 0x43};
  must_ok(shoots_provider_request_mint_internal(engine,
                                                session,
                                                1,
                                                1,
                                                "tool.exec",
                                                &provider,
                                                0x1u,
                                                0x1111ULL,
                                                arg_blob,
                                                (uint32_t)sizeof(arg_blob),
                                                &request,
                                                &error),
          "mint request", &error);

  shoots_provider_receipt_t receipt;
  memset(&receipt, 0, sizeof(receipt));
  receipt.session_id = request.session_id;
  receipt.plan_id = request.plan_id;
  receipt.execution_slot = request.execution_slot;
  receipt.request_id = request.request_id;
  receipt.provider_id_len = request.provider_id_len;
  memcpy(receipt.provider_id, request.provider_id, request.provider_id_len + 1);
  receipt.tool_id_len = request.tool_id_len;
  memcpy(receipt.tool_id, request.tool_id, request.tool_id_len + 1);
  receipt.tool_version = request.tool_version;
  receipt.input_hash = request.input_hash;
  receipt.result_code = SHOOTS_PROVIDER_RESULT_SUCCESS;
  receipt.output_size = 2;
  receipt.output_blob[0] = 0x4f;
  receipt.output_blob[1] = 0x4b;
  must_ok(shoots_provider_receipt_import_internal(engine, &receipt, &error),
          "import receipt", &error);
}

static char *serialize_ledger(const shoots_engine_t *engine) {
  size_t total = 1;
  const shoots_ledger_entry_t *entry = engine->ledger_head;
  while (entry != NULL) {
    total += 32;
    if (entry->payload != NULL) {
      total += strlen(entry->payload);
    }
    entry = entry->next;
  }
  char *buffer = (char *)malloc(total);
  assert(buffer != NULL);
  buffer[0] = '\0';
  size_t offset = 0;
  entry = engine->ledger_head;
  while (entry != NULL) {
    int written = snprintf(buffer + offset, total - offset, "%u:%s\n",
                           (unsigned)entry->type,
                           entry->payload != NULL ? entry->payload : "");
    assert(written >= 0);
    offset += (size_t)written;
    entry = entry->next;
  }
  return buffer;
}

int main(void) {
  shoots_error_info_t error;
  shoots_engine_t *first = create_engine_or_die();
  shoots_engine_t *second = create_engine_or_die();

  run_single_roundtrip(first);
  run_single_roundtrip(second);

  char *first_ledger = serialize_ledger(first);
  char *second_ledger = serialize_ledger(second);
  assert(strcmp(first_ledger, second_ledger) == 0);

  free(first_ledger);
  free(second_ledger);

  must_ok(shoots_engine_destroy(first, &error), "destroy first", &error);
  must_ok(shoots_engine_destroy(second, &error), "destroy second", &error);
  return 0;
}
