#include "shoots/shoots.h"
#include "always_assert.h"

#include <string.h>

static void must_ok(shoots_error_code_t code,
                    const char *step,
                    shoots_error_info_t *error) {
  if (code == SHOOTS_OK) {
    return;
  }
  (void)error;
  shoots_test_assert_fail(step, __FILE__, __LINE__);
}

int main(void) {
  shoots_config_t config;
  memset(&config, 0, sizeof(config));
  config.model_root_path = ".";
  config.max_memory_bytes = 1024u * 1024u;
  config.max_execution_steps = 64u;

  shoots_error_info_t error;
  shoots_engine_t *engine = NULL;
  must_ok(shoots_engine_create(&config, &engine, &error),
          "shoots_engine_create",
          &error);

  shoots_model_t *invalid_model = NULL;
  assert(shoots_model_load(engine, "", &invalid_model, &error) == SHOOTS_ERR_INVALID_ARGUMENT);
  assert(invalid_model == NULL);

  shoots_model_t *model_a = NULL;
  shoots_model_t *model_b = NULL;
  must_ok(shoots_model_load(engine, "model-id", &model_a, &error),
          "shoots_model_load(model-a)",
          &error);
  must_ok(shoots_model_load(engine, "model-alt", &model_b, &error),
          "shoots_model_load(model-b)",
          &error);

  const uint32_t input_tokens[] = {11u, 22u, 33u};
  shoots_inference_request_t infer_request;
  memset(&infer_request, 0, sizeof(infer_request));
  infer_request.model = model_a;
  infer_request.input_tokens = input_tokens;
  infer_request.input_token_count = sizeof(input_tokens) / sizeof(input_tokens[0]);
  infer_request.max_output_tokens = 8u;
  infer_request.max_execution_steps = 64u;

  shoots_inference_response_t infer_first;
  shoots_inference_response_t infer_second;
  memset(&infer_first, 0, sizeof(infer_first));
  memset(&infer_second, 0, sizeof(infer_second));

  assert(shoots_infer(engine, &infer_request, &infer_first, &error) ==
         SHOOTS_ERR_UNSUPPORTED);
  assert(infer_first.output_tokens == NULL);
  assert(infer_first.output_token_count == 0);
  assert(infer_first.stop_reason == 0);
  assert(infer_first.input_token_count == 0);

  infer_request.model = model_b;
  assert(shoots_infer(engine, &infer_request, &infer_second, &error) ==
         SHOOTS_ERR_UNSUPPORTED);
  assert(infer_second.output_tokens == NULL);
  assert(infer_second.output_token_count == 0);

  shoots_inference_request_t limited_request = infer_request;
  limited_request.model = model_a;
  limited_request.max_execution_steps = infer_request.input_token_count;
  shoots_inference_response_t limited_response;
  memset(&limited_response, 0, sizeof(limited_response));
  assert(shoots_infer(engine, &limited_request, &limited_response, &error) ==
         SHOOTS_ERR_UNSUPPORTED);
  assert(limited_response.output_tokens == NULL);
  assert(limited_response.output_token_count == 0);

  shoots_inference_request_t invalid_infer = infer_request;
  invalid_infer.model = model_a;
  invalid_infer.input_tokens = NULL;
  invalid_infer.input_token_count = 1;
  assert(shoots_infer(engine, &invalid_infer, &limited_response, &error) ==
         SHOOTS_ERR_INVALID_ARGUMENT);

  shoots_embedding_request_t embed_request;
  memset(&embed_request, 0, sizeof(embed_request));
  embed_request.model = model_a;
  embed_request.input_tokens = input_tokens;
  embed_request.input_token_count = sizeof(input_tokens) / sizeof(input_tokens[0]);
  embed_request.max_execution_steps = 64u;

  shoots_embedding_response_t embed_first;
  shoots_embedding_response_t embed_second;
  shoots_embedding_response_t embed_other_model;
  memset(&embed_first, 0, sizeof(embed_first));
  memset(&embed_second, 0, sizeof(embed_second));
  memset(&embed_other_model, 0, sizeof(embed_other_model));

  assert(shoots_embed(engine, &embed_request, &embed_first, &error) ==
         SHOOTS_ERR_UNSUPPORTED);
  assert(embed_first.embedding == NULL);
  assert(embed_first.embedding_length == 0);
  assert(embed_first.input_token_count == 0);

  embed_request.model = model_b;
  assert(shoots_embed(engine, &embed_request, &embed_second, &error) ==
         SHOOTS_ERR_UNSUPPORTED);
  assert(embed_second.embedding == NULL);
  assert(embed_second.embedding_length == 0);

  shoots_embedding_request_t limited_embed = embed_request;
  limited_embed.model = model_a;
  limited_embed.max_execution_steps = 1u;
  assert(shoots_embed(engine, &limited_embed, &embed_other_model, &error) ==
         SHOOTS_ERR_UNSUPPORTED);
  assert(embed_other_model.embedding == NULL);
  assert(embed_other_model.embedding_length == 0);

  must_ok(shoots_model_unload(engine, model_a, &error),
          "shoots_model_unload(model-a)",
          &error);
  must_ok(shoots_model_unload(engine, model_b, &error),
          "shoots_model_unload(model-b)",
          &error);
  must_ok(shoots_engine_destroy(engine, &error),
          "shoots_engine_destroy",
          &error);
  return 0;
}
