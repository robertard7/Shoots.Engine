# Integration Examples (Non-Executable)

These examples are illustrative pseudocode only. They are not runnable code.
They show call ordering, ownership, and error handling requirements.

## C (Pseudocode)

```
// Prepare configuration with explicit capability flags.
config.model_root_path = "path";
config.max_memory_bytes = ...;
config.allow_background_threads = 0;
config.allow_filesystem_io = 0;
config.allow_network_io = 0;

err_info = {0};
rc = shoots_engine_create(&config, &engine, &err_info);
if (rc != SHOOTS_OK) { handle_error(rc, err_info); }

// Optional model load.
rc = shoots_model_load(engine, "model-id", &model, &err_info);
if (rc != SHOOTS_OK) { handle_error(rc, err_info); }

// Inference call shape.
request.model = model;
request.input_tokens = input_tokens;
request.input_token_count = input_count;
request.max_output_tokens = max_out;
request.max_execution_steps = max_steps;
rc = shoots_infer(engine, &request, &response, &err_info);
if (rc != SHOOTS_OK) { handle_error(rc, err_info); }

// Engine-owned buffers must be freed by the host.
shoots_engine_free(engine, response.output_tokens, &err_info);

// Unload and destroy.
shoots_model_unload(engine, model, &err_info);
shoots_engine_destroy(engine, &err_info);
```

## C++ (Pseudocode)

```
// Use the C ABI (`extern "C"`) calls directly.
shoots_config_t config = {};
config.allow_background_threads = 0;
config.allow_filesystem_io = 0;
config.allow_network_io = 0;

shoots_error_info_t err = {};
shoots_engine_t* engine = nullptr;
auto rc = shoots_engine_create(&config, &engine, &err);
if (rc != SHOOTS_OK) { handle_error(rc, err); }

// Optional model load and embed call shape.
shoots_model_t* model = nullptr;
rc = shoots_model_load(engine, "model-id", &model, &err);
if (rc != SHOOTS_OK) { handle_error(rc, err); }

shoots_embedding_request_t req = {};
req.model = model;
req.input_tokens = input_tokens;
req.input_token_count = input_count;
req.max_execution_steps = max_steps;
shoots_embedding_response_t resp = {};
rc = shoots_embed(engine, &req, &resp, &err);
if (rc != SHOOTS_OK) { handle_error(rc, err); }

shoots_engine_free(engine, resp.embedding, &err);
shoots_model_unload(engine, model, &err);
shoots_engine_destroy(engine, &err);
```

## Rust (Pseudocode)

```
// Pseudocode outline using FFI bindings.
let mut config = shoots_config {
  allow_background_threads: 0,
  allow_filesystem_io: 0,
  allow_network_io: 0,
  // other fields...
};

let mut err = shoots_error_info::default();
let mut engine: *mut shoots_engine = null_mut();
let rc = shoots_engine_create(&config, &mut engine, &mut err);
if rc != SHOOTS_OK { handle_error(rc, err); }

// Optional model load and inference call shape.
let mut model: *mut shoots_model = null_mut();
let rc = shoots_model_load(engine, "model-id", &mut model, &mut err);
if rc != SHOOTS_OK { handle_error(rc, err); }

let mut request = shoots_inference_request { model, /* tokens... */ };
let mut response = shoots_inference_response::default();
let rc = shoots_infer(engine, &request, &mut response, &mut err);
if rc != SHOOTS_OK { handle_error(rc, err); }

// Free engine-owned buffers via the engine.
shoots_engine_free(engine, response.output_tokens, &mut err);

shoots_model_unload(engine, model, &mut err);
shoots_engine_destroy(engine, &mut err);
```

## Zig (Pseudocode)

```
// Pseudocode outline using C ABI bindings.
var config: shoots_config = .{
  .allow_background_threads = 0,
  .allow_filesystem_io = 0,
  .allow_network_io = 0,
  // other fields...
};

var err: shoots_error_info = undefined;
var engine: *shoots_engine = undefined;
const rc = shoots_engine_create(&config, &engine, &err);
if (rc != SHOOTS_OK) { handle_error(rc, err); }

// Optional model load and embed call shape.
var model: *shoots_model = undefined;
if (shoots_model_load(engine, "model-id", &model, &err) != SHOOTS_OK) {
  handle_error(rc, err);
}

var request: shoots_embedding_request = .{ .model = model, /* tokens... */ };
var response: shoots_embedding_response = undefined;
if (shoots_embed(engine, &request, &response, &err) != SHOOTS_OK) {
  handle_error(rc, err);
}

shoots_engine_free(engine, response.embedding, &err);
shoots_model_unload(engine, model, &err);
shoots_engine_destroy(engine, &err);
```

## Shared Notes

- Error handling uses `shoots_error_info_t` with explicit error codes.
- The host owns input buffers; the engine owns output buffers.
- Capabilities (threads, filesystem IO, network IO) are disabled unless explicitly enabled.
- No threading or IO is performed unless allowed by configuration.
