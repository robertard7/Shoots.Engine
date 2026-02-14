#ifndef SHOOTS_ENGINE_TEST_SUPPORT_H
#define SHOOTS_ENGINE_TEST_SUPPORT_H

#include "engine_internal.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline void test_must_ok(shoots_error_code_t code,
                                const char *step,
                                shoots_error_info_t *error) {
  if (code == SHOOTS_OK) {
    return;
  }
  fprintf(stderr, "%s failed: code=%d message=%s\n",
          step,
          (int)code,
          (error != NULL && error->message != NULL) ? error->message : "(none)");
  assert(0 && "test step failed");
}

static inline shoots_engine_t *test_create_engine(void) {
  shoots_config_t config;
  memset(&config, 0, sizeof(config));
  config.model_root_path = ".";
  config.max_memory_bytes = 1024u * 1024u;
  config.max_execution_steps = 1024u;

  shoots_engine_t *engine = NULL;
  shoots_error_info_t error;
  test_must_ok(shoots_engine_create(&config, &engine, &error),
               "shoots_engine_create",
               &error);
  return engine;
}

static inline void test_register_provider_tool_and_lock(
  shoots_engine_t *engine,
  shoots_provider_descriptor_t *out_provider) {
  shoots_error_info_t error;
  shoots_provider_descriptor_t provider;
  memset(&provider, 0, sizeof(provider));
  provider.provider_id_len = 5;
  memcpy(provider.provider_id, "provA", provider.provider_id_len + 1);
  provider.supported_tool_categories = SHOOTS_PROVIDER_TOOL_CATEGORY_EXECUTION;
  provider.max_concurrency = 8;
  provider.guarantees_mask = SHOOTS_PROVIDER_GUARANTEE_DETERMINISTIC;

  test_must_ok(shoots_provider_register_internal(engine, &provider, &error),
               "shoots_provider_register_internal",
               &error);

  engine->tools_locked = 0;
  shoots_tool_constraints_t constraints = {8, 64, SHOOTS_TOOL_CONFIRM_NONE};
  shoots_tool_record_t *tool_record = NULL;
  test_must_ok(shoots_tool_register_internal(engine,
                                             "tool.exec",
                                             SHOOTS_TOOL_CATEGORY_EXECUTION,
                                             1,
                                             0x3u,
                                             &constraints,
                                             SHOOTS_TOOL_DETERMINISM_DETERMINISTIC,
                                             &tool_record,
                                             &error),
               "shoots_tool_register_internal",
               &error);
  assert(tool_record != NULL);

  engine->tools_locked = 1;
  test_must_ok(shoots_provider_registry_lock_internal(engine, &error),
               "shoots_provider_registry_lock_internal",
               &error);

  if (out_provider != NULL) {
    *out_provider = provider;
  }
}

static inline shoots_session_t *test_create_session_with_plan(shoots_engine_t *engine,
                                                              const char *intent_id,
                                                              uint64_t plan_id) {
  shoots_error_info_t error;
  shoots_session_t *session = NULL;
  test_must_ok(shoots_session_create_internal(engine,
                                              intent_id,
                                              SHOOTS_SESSION_MODE_TRANSACTIONAL,
                                              &session,
                                              &error),
               "shoots_session_create_internal",
               &error);
  const char *tool_ids[1] = {"tool.exec"};
  shoots_tool_reject_reason_t reasons[1];
  memset(reasons, 0, sizeof(reasons));
  reasons[0].code = SHOOTS_TOOL_REJECT_OK;
  memcpy(reasons[0].token, "ok", 3);
  test_must_ok(shoots_session_plan_store_internal(session,
                                                  plan_id,
                                                  0x424242ULL,
                                                  tool_ids,
                                                  reasons,
                                                  1,
                                                  &error),
               "shoots_session_plan_store_internal",
               &error);
  return session;
}

static inline shoots_provider_request_t test_mint_request(shoots_engine_t *engine,
                                                          shoots_session_t *session,
                                                          const shoots_provider_descriptor_t *provider,
                                                          uint64_t plan_id,
                                                          uint64_t execution_slot,
                                                          uint64_t input_hash) {
  shoots_error_info_t error;
  shoots_provider_request_t request;
  memset(&request, 0, sizeof(request));
  const uint8_t arg_blob[] = {0x41, 0x42, 0x43};
  test_must_ok(shoots_provider_request_mint_internal(engine,
                                                     session,
                                                     plan_id,
                                                     execution_slot,
                                                     "tool.exec",
                                                     provider,
                                                     0x1u,
                                                     input_hash,
                                                     arg_blob,
                                                     (uint32_t)sizeof(arg_blob),
                                                     &request,
                                                     &error),
               "shoots_provider_request_mint_internal",
               &error);
  return request;
}

static inline shoots_provider_receipt_t test_make_receipt_success(
  const shoots_provider_request_t *request) {
  shoots_provider_receipt_t receipt;
  memset(&receipt, 0, sizeof(receipt));
  receipt.session_id = request->session_id;
  receipt.plan_id = request->plan_id;
  receipt.execution_slot = request->execution_slot;
  receipt.request_id = request->request_id;
  receipt.provider_id_len = request->provider_id_len;
  memcpy(receipt.provider_id, request->provider_id, request->provider_id_len + 1);
  receipt.tool_id_len = request->tool_id_len;
  memcpy(receipt.tool_id, request->tool_id, request->tool_id_len + 1);
  receipt.tool_version = request->tool_version;
  receipt.input_hash = request->input_hash;
  receipt.result_code = SHOOTS_PROVIDER_RESULT_SUCCESS;
  receipt.output_size = 2;
  receipt.output_blob[0] = 0x4f;
  receipt.output_blob[1] = 0x4b;
  return receipt;
}

static inline size_t test_pending_count(shoots_engine_t *engine) {
  shoots_error_info_t error;
  shoots_provider_request_record_t *pending = NULL;
  size_t pending_count = 0;
  test_must_ok(shoots_engine_export_pending_provider_requests_const(engine,
                                                                    &pending,
                                                                    &pending_count,
                                                                    &error),
               "shoots_engine_export_pending_provider_requests_const",
               &error);
  if (pending != NULL) {
    test_must_ok(shoots_engine_free(engine, pending, &error),
                 "shoots_engine_free(pending)",
                 &error);
  }
  return pending_count;
}

static inline char *test_serialize_ledger(const shoots_engine_t *engine) {
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
    int written = snprintf(buffer + offset,
                           total - offset,
                           "%u:%s\n",
                           (unsigned)entry->type,
                           entry->payload != NULL ? entry->payload : "");
    assert(written >= 0);
    offset += (size_t)written;
    entry = entry->next;
  }
  return buffer;
}

#endif
