# Shoots.Engine Status

## Engine completion checklist
- [x] Release builds: `shoots_engine_static` and `shoots_engine_shared`.
- [x] Root CTest discovery and pass.
- [x] Provider frozen export signatures locked by compile guard.
- [x] Determinism replay tests for provider round-trip.
- [x] Guardrails for malformed receipts, session isolation, ordering, snapshot contract, and overflow failure behavior.
- [x] Symbol-stub guard for `commands.c` and `core_engine.c`.
- [x] Consumer examples for static and shared linkage.

## Frozen provider export APIs
- `shoots_engine_export_provider_snapshot_const`
- `shoots_engine_export_pending_provider_requests_const`
- `shoots_engine_provider_ready`

## Ownership contract
- Snapshot export returns engine-owned allocations; caller frees through `shoots_engine_free`.
- Pending request export returns engine-owned allocations; caller frees through `shoots_engine_free`.
- Free-after-engine-destroy is invalid by contract.

## Test inventory
- `provider_roundtrip_(static|shared)_test`
- `determinism_replay_(static|shared)_test`
- `guardrail_limits_(static|shared)_test`
- `malformed_receipt_(static|shared)_test`
- `multi_request_ordering_(static|shared)_test`
- `multi_session_isolation_(static|shared)_test`
- `snapshot_contract_(static|shared)_test`
- `oom_guardrails_(static|shared)_test`
- `headers_smoke`, `public_headers_smoke`, `provider_exports_signature`

## Known limitations
- Provider snapshot payload is validated as deterministic text contract but not a binary schema.
- Memory-failure injection hooks are not currently exposed; failure-path testing uses deterministic bounds/contract failures.

Engine complete, Shoots work resumes.
