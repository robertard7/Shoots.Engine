# Goals

## Phase 4 Goals — Deterministic Core Implementation
- Implement engine lifecycle with deterministic create/destroy behavior.
- Validate configuration inputs with explicit failure on missing values.
- Track engine-owned memory against configured limits.
- Keep inference and embedding logic out of the codebase.
- Lock lifecycle behavior for ABI stability.

## Explicitly Deferred
- Any inference or embedding implementation.
- Model execution or tokenization.
- Tests, harnesses, or CI integration.
- Host adapters or Shoots integration.

If it is not listed above, it is out of scope.
