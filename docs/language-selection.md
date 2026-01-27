# Language Selection (Locked)

## Decision
The implementation language for Shoots.Engine is **ISO C (C17)**.

This decision is **locked** for Phase 2 and future phases.

## Rationale
- **Portability**: C17 is supported across major platforms and toolchains.
- **Embeddability**: Minimal runtime requirements and straightforward static or shared linking.
- **Determinism**: No mandatory runtime services or hidden concurrency features.
- **ABI Compatibility**: Direct alignment with a stable C ABI surface.
- **Operational Simplicity**: No required standard library features beyond explicit, controlled usage.

## Rejected Alternatives
- **C++**: Exception handling, RTTI, and ABI variability across compilers complicate stability.
- **Rust**: Toolchain and ABI stability for long-term C-facing interfaces is still evolving.
- **Zig**: Ecosystem maturity and long-term ABI stability are not yet proven.
- **Go**: Garbage collection and runtime services conflict with deterministic embedding goals.
- **Managed languages**: Require runtimes that violate embeddability and determinism constraints.
