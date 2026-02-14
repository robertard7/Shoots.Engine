# Shoots.Engine Tests

## Canonical invocations
- Root build/test:
  - `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release`
  - `cmake --build build --config Release -j`
  - `ctest --test-dir build --output-on-failure`
- Engine-only build/test:
  - `cmake -S tools/engine -B build-engine -DCMAKE_BUILD_TYPE=Release`
  - `cmake --build build-engine --config Release -j`
  - `ctest --test-dir build-engine --output-on-failure`

## Frozen provider export ownership contract
- `shoots_engine_export_provider_snapshot_const` allocates a snapshot wrapper and payload using engine allocator.
- Caller must free `snapshot->payload` first via `shoots_engine_free(engine, snapshot->payload, ...)`, then free `snapshot` via `shoots_engine_free(engine, snapshot, ...)`.
- `shoots_engine_export_pending_provider_requests_const` allocates a contiguous array with engine allocator.
- Caller must release that array with `shoots_engine_free(engine, list, ...)`.
- `shoots_engine_free` after `shoots_engine_destroy` is invalid and rejected.

## Provider frozen exports
- `shoots_engine_export_provider_snapshot_const`
- `shoots_engine_export_pending_provider_requests_const`
- `shoots_engine_provider_ready`

Signature-lock tests compile these through typed function pointers (`provider_exports_signature`).
