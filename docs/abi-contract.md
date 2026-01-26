# C ABI Contract

## Overview
This document defines the stable C ABI surface for Shoots.Engine. The ABI is language-agnostic and uses opaque handles with explicit ownership rules.

## ABI Types
```c
typedef struct shoots_engine shoots_engine_t;
typedef struct shoots_model shoots_model_t;
```

## Scalar Types
```c
#include <stddef.h>
#include <stdint.h>
```

## Error Codes
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

typedef enum shoots_error_severity {
  SHOOTS_SEVERITY_RECOVERABLE = 0,
  SHOOTS_SEVERITY_FATAL = 1
} shoots_error_severity_t;
```

## Error Info
```c
typedef struct shoots_error_info {
  shoots_error_code_t code;
  shoots_error_severity_t severity;
  const char *message;
} shoots_error_info_t;
```

### Error Propagation Rules
- Every function returns `shoots_error_code_t`.
- `shoots_error_info_t` is optional and may be null.
- `message` is human-readable and may be null.
- The engine performs no logging or side effects when populating errors.

## Configuration
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

### Configuration Ownership
- The host owns all configuration memory.
- Configuration values are read-only during engine creation.
- Configuration is immutable after creation.

## Engine Lifecycle
```c
shoots_error_code_t shoots_engine_create(
  const shoots_config_t *config,
  shoots_engine_t **out_engine,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_engine_destroy(
  shoots_engine_t *engine,
  shoots_error_info_t *out_error);
```

### Lifecycle Ownership
- `out_engine` receives an engine-owned handle.
- The host must call `shoots_engine_destroy` to release the handle.
- The engine never self-starts and never spawns threads unless enabled.

## Memory Management
```c
shoots_error_code_t shoots_engine_free(
  shoots_engine_t *engine,
  void *buffer,
  shoots_error_info_t *out_error);
```

### Memory Ownership
- Any buffer allocated by the engine must be released with `shoots_engine_free`.
- The host retains ownership of all input buffers.

## Inference
```c
typedef struct shoots_inference_request {
  shoots_model_t *model;
  const uint32_t *input_tokens;
  size_t input_token_count;
  uint32_t max_output_tokens;
  uint64_t max_execution_steps;
} shoots_inference_request_t;

typedef struct shoots_inference_response {
  uint32_t *output_tokens;
  size_t output_token_count;
  uint32_t stop_reason;
  uint32_t input_token_count;
} shoots_inference_response_t;

shoots_error_code_t shoots_infer(
  shoots_engine_t *engine,
  const shoots_inference_request_t *request,
  shoots_inference_response_t *response,
  shoots_error_info_t *out_error);
```

### Inference Ownership
- The host owns the request and input token buffers.
- The engine owns `output_tokens` and must allocate it.
- The host must release `output_tokens` with `shoots_engine_free`.

## Embeddings
```c
typedef struct shoots_embedding_request {
  shoots_model_t *model;
  const uint32_t *input_tokens;
  size_t input_token_count;
  uint64_t max_execution_steps;
} shoots_embedding_request_t;

typedef struct shoots_embedding_response {
  float *embedding;
  size_t embedding_length;
  uint32_t input_token_count;
} shoots_embedding_response_t;

shoots_error_code_t shoots_embed(
  shoots_engine_t *engine,
  const shoots_embedding_request_t *request,
  shoots_embedding_response_t *response,
  shoots_error_info_t *out_error);
```

### Embedding Ownership
- The host owns the request and input token buffers.
- The engine owns `embedding` and must allocate it.
- The host must release `embedding` with `shoots_engine_free`.

## Model Handles
Model loading is defined as part of the ABI surface without specifying implementation details.

```c
shoots_error_code_t shoots_model_load(
  shoots_engine_t *engine,
  const char *model_identifier,
  shoots_model_t **out_model,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_model_unload(
  shoots_engine_t *engine,
  shoots_model_t *model,
  shoots_error_info_t *out_error);
```

### Model Ownership
- `out_model` receives an engine-owned handle.
- The host must call `shoots_model_unload` to release the handle.

## ABI Error Mapping Addendum
- Error codes map directly to `shoots_error_code_t` values.
- Severity maps to `shoots_error_severity_t`.
- Fatal errors require destroying the engine instance before reuse.
- Errors never cross the ABI as exceptions or out-of-band logs.
