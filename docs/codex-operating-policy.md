---

## Status

This repository is intentionally minimal.

**Phase 9 (Session Continuity Core) is locked.** The repository must:
- Implement only engine lifecycle, configuration validation, and memory accounting.
- Contain no inference, embedding, or model execution logic.
- Treat the task board as the authoritative roadmap.
- Preserve deterministic, embeddable constraints.
- Treat lifecycle semantics as locked for ABI stability.
- Treat model handle load/unload and engine destroy semantics as locked for this phase.
- Treat provider runtime lifecycle and capability lock-down as locked for Phase 8.
- Treat session continuity (sessions, chat buffer, ledger, command memory) as locked for Phase 9.
- Treat ABI snapshot, FFI audit, and static/shared parity documentation as locked for Phase 6.
- Treat host responsibility, capability declaration, and integration examples as locked for Phase 7.

Everything else comes later.

---

## License

(TBD)
