# Public ABI Surface Snapshot

This snapshot mirrors `tools/engine/include/shoots/shoots.h` and records the public
ABI-relevant declarations for stable reference.

## Opaque Types

```c
typedef struct shoots_engine shoots_engine_t;
typedef struct shoots_model shoots_model_t;
```

## Enumerations

```c
typedef enum shoots_error_code {
  SHOOTS_OK = 0,
  SHOOTS_ERR_INVALID_ARGUMENT = 1,
  SHOOTS_ERR_INVALID_STATE = 2,
  SHOOTS_ERR_OUT_OF_MEMORY = 3,
  SHOOTS_ERR_RESOURCE_UNAVAILABLE = 4,
  SHOOTS_ERR_UNSUPPORTED = 5,
  SHOOTS_ERR_INTERNAL_FAILURE = 6
} shoots_error_code_t;
```

```c
typedef enum shoots_error_severity {
  SHOOTS_SEVERITY_RECOVERABLE = 0,
  SHOOTS_SEVERITY_FATAL = 1
} shoots_error_severity_t;
```

## Struct Layouts (Field Order)

```c
typedef struct shoots_error_info {
  shoots_error_code_t code;
  shoots_error_severity_t severity;
  const char *message;
} shoots_error_info_t;
```

```c
typedef struct shoots_config {
  const char *model_root_path;
  size_t max_memory_bytes;
  uint64_t max_execution_steps;
  uint8_t allow_background_threads;
  uint8_t allow_filesystem_io;
  uint8_t allow_network_io;
} shoots_config_t;
```

```c
typedef struct shoots_inference_request {
  shoots_model_t *model;
  const uint32_t *input_tokens;
  size_t input_token_count;
  uint32_t max_output_tokens;
  uint64_t max_execution_steps;
} shoots_inference_request_t;
```

```c
typedef struct shoots_inference_response {
  uint32_t *output_tokens;
  size_t output_token_count;
  uint32_t stop_reason;
  uint32_t input_token_count;
} shoots_inference_response_t;
```

```c
typedef struct shoots_embedding_request {
  shoots_model_t *model;
  const uint32_t *input_tokens;
  size_t input_token_count;
  uint64_t max_execution_steps;
} shoots_embedding_request_t;
```

```c
typedef struct shoots_embedding_response {
  float *embedding;
  size_t embedding_length;
  uint32_t input_token_count;
} shoots_embedding_response_t;
```

## Public API Functions

```c
shoots_error_code_t shoots_engine_create(
  const shoots_config_t *config,
  shoots_engine_t **out_engine,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_engine_destroy(
  shoots_engine_t *engine,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_engine_free(
  shoots_engine_t *engine,
  void *buffer,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_model_load(
  shoots_engine_t *engine,
  const char *model_identifier,
  shoots_model_t **out_model,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_model_unload(
  shoots_engine_t *engine,
  shoots_model_t *model,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_infer(
  shoots_engine_t *engine,
  const shoots_inference_request_t *request,
  shoots_inference_response_t *response,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_embed(
  shoots_engine_t *engine,
  const shoots_embedding_request_t *request,
  shoots_embedding_response_t *response,
  shoots_error_info_t *out_error);
```

## Header FFI Audit (Phase 6.2)

### C++ Compatibility
- The header uses `extern "C"` guards for C++ callers.
- All exposed declarations are C-compatible and avoid C++-only constructs.

### Rust / Zig FFI Safety
- No flexible array members.
- No compiler-specific packing pragmas or attributes.
- Integer fields use fixed-width types (`uint32_t`, `uint64_t`, `uint8_t`) where size is required.
- Opaque handles are forward-declared and only passed by pointer.

### ABI Notes / Hazards
- `size_t` appears in multiple structs; its width is platform-defined and must be mirrored
  with `usize` in Rust or `usize` in Zig for FFI bindings.
- C enum underlying size is implementation-defined; bindings should mirror the C ABI
  (`repr(C)` in Rust or explicit enum backing type in Zig) rather than assuming `int32_t`.

## Static vs Shared Parity (Phase 6.3)

- Both static and shared targets are built from the same `tools/engine/src` sources.
- No conditional compilation toggles or symbol differences are defined between the targets.
- Exported API functions are identical across static and shared builds.
