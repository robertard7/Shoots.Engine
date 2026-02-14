#include "engine_internal.h"

#include <stdio.h>
#include <string.h>

int main(void) {
  shoots_config_t config;
  memset(&config, 0, sizeof(config));
  config.model_root_path = ".";
  config.max_memory_bytes = 1024u * 1024u;
  config.max_execution_steps = 1024u;

  shoots_engine_t *engine = NULL;
  shoots_error_info_t error;
  if (shoots_engine_create(&config, &engine, &error) != SHOOTS_OK) {
    return 1;
  }

  shoots_provider_descriptor_t provider;
  memset(&provider, 0, sizeof(provider));
  provider.provider_id_len = 5;
  memcpy(provider.provider_id, "provA", provider.provider_id_len + 1);
  provider.supported_tool_categories = SHOOTS_PROVIDER_TOOL_CATEGORY_EXECUTION;
  provider.max_concurrency = 8;
  provider.guarantees_mask = SHOOTS_PROVIDER_GUARANTEE_DETERMINISTIC;

  if (shoots_provider_register_internal(engine, &provider, &error) != SHOOTS_OK) {
    shoots_engine_destroy(engine, &error);
    return 2;
  }

  engine->tools_locked = 0;
  shoots_tool_constraints_t constraints = {8, 64, SHOOTS_TOOL_CONFIRM_NONE};
  shoots_tool_record_t *tool_record = NULL;
  if (shoots_tool_register_internal(engine,
                                    "tool.exec",
                                    SHOOTS_TOOL_CATEGORY_EXECUTION,
                                    1,
                                    0x3u,
                                    &constraints,
                                    SHOOTS_TOOL_DETERMINISM_DETERMINISTIC,
                                    &tool_record,
                                    &error) != SHOOTS_OK ||
      (engine->tools_locked = 1, shoots_provider_registry_lock_internal(engine, &error) != SHOOTS_OK)) {
    shoots_engine_destroy(engine, &error);
    return 3;
  }

  shoots_session_t *session = NULL;
  if (shoots_session_create_internal(engine,
                                     "intent-consumer-shared",
                                     SHOOTS_SESSION_MODE_TRANSACTIONAL,
                                     &session,
                                     &error) != SHOOTS_OK) {
    shoots_engine_destroy(engine, &error);
    return 4;
  }

  const char *tool_ids[1] = {"tool.exec"};
  shoots_tool_reject_reason_t reasons[1];
  memset(reasons, 0, sizeof(reasons));
  reasons[0].code = SHOOTS_TOOL_REJECT_OK;
  memcpy(reasons[0].token, "ok", 3);
  if (shoots_session_plan_store_internal(session,
                                         1,
                                         0x424242ULL,
                                         tool_ids,
                                         reasons,
                                         1,
                                         &error) != SHOOTS_OK) {
    shoots_engine_destroy(engine, &error);
    return 5;
  }

  shoots_provider_request_t request;
  memset(&request, 0, sizeof(request));
  const uint8_t arg_blob[] = {0x41, 0x42, 0x43};
  if (shoots_provider_request_mint_internal(engine,
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
                                            &error) != SHOOTS_OK) {
    shoots_engine_destroy(engine, &error);
    return 6;
  }

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

  if (shoots_provider_receipt_import_internal(engine, &receipt, &error) != SHOOTS_OK) {
    shoots_engine_destroy(engine, &error);
    return 7;
  }

  printf("consumer_shared_roundtrip_ok\n");

  if (shoots_engine_destroy(engine, &error) != SHOOTS_OK) {
    return 8;
  }
  return 0;
}
