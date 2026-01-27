---

## Status

This repository is intentionally minimal.

**Phase 4 (Deterministic Core Implementation) is active.** The repository must:
- Implement only engine lifecycle, configuration validation, and memory accounting.
- Contain no inference, embedding, or model execution logic.
- Treat the task board as the authoritative roadmap.
- Preserve deterministic, embeddable constraints.
- Treat lifecycle semantics as locked for ABI stability.
- Treat model handle load/unload and engine destroy semantics as locked for this phase.
- Treat ABI snapshot, FFI audit, and static/shared parity documentation as locked for Phase 6.

Everything else comes later.

---

## License

(TBD)
