# Goals

## Phase 4 Goals — Deterministic Core Implementation
- Implement engine lifecycle with deterministic create/destroy behavior.
- Validate configuration inputs with explicit failure on missing values.
- Track engine-owned memory against configured limits.
- Keep inference and embedding logic out of the codebase.
- Lock lifecycle behavior for ABI stability.
- Provide deterministic model handle load/unload with engine-owned registry.

## Phase 10 Goals — Provider Execution Spine
- Introduce intent-to-command binding with internal intent records.
- Enforce per-session command ordering with execution slots.
- Canonicalize command results in engine-owned result records.
- Propagate deterministic failure state through ledger entries.

## Explicitly Deferred
- Any inference or embedding implementation.
- Model execution or tokenization.
- Tests, harnesses, or CI integration.
- Host adapters or Shoots integration.

If it is not listed above, it is out of scope.

## Phase 6 Lock — ABI & Integration Prep
- ABI surface snapshot, FFI audit, and static/shared parity are locked for this phase.

## Phase 7 Lock — Host & Integration Contracts
- Host responsibility contract, capability declaration, and integration examples are locked.
- No further Phase 7 contract changes without a phase bump.

## Phase 8 Lock — Provider Runtime Hardening
- Provider runtime lifecycle/state machine semantics are locked.
- Provider capability lockdown and stubbed execution entrypoints are locked.
- No further Phase 8 runtime behavior changes without a phase bump.

## Phase 9 Lock — Session Continuity Core
- Session handle, rolling chat buffer, context ledger, and command memory semantics are locked.
- No further Phase 9 continuity behavior changes without a phase bump.

## Phase 10 Lock — Provider Execution Spine
- Intent record binding, execution slot ordering, result canonicalization, and deterministic failure propagation are locked.
- No further Phase 10 execution behavior changes without a phase bump.
