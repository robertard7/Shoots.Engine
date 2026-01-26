# Shoots.Engine

Shoots.Engine is a **portable, embeddable AI runtime engine**.

It is designed to be:
- **Embedded directly inside applications**
- **Optionally hosted as a local service**
- **Shippable with operating systems and standalone programs**
- **Deterministic, side-effect controlled, and infrastructure-grade**

This repository contains the **engine only**.

---

## Scope (Strict)

Shoots.Engine is responsible for:
- Local model loading
- Inference execution
- Embedding generation
- Memory and lifecycle control
- Deterministic request/response behavior

Shoots.Engine is **not**:
- A UI
- A chatbot product
- An agent framework
- A workflow/orchestration system
- A build tool
- A network service by default

Those responsibilities belong elsewhere.

---

## Design Principles

- **Library-first**: The engine must function fully when embedded.
- **Deterministic**: Same inputs + same model = same outputs.
- **Explicit control**: No hidden defaults, no magic behavior.
- **No side effects by default**:  
  - No networking  
  - No background threads unless explicitly started  
  - No filesystem writes unless explicitly requested
- **Stable ABI**: Designed to be consumed from multiple languages.

Think **SQLite**, not a web service.

---

## Architecture Overview

The engine is structured in layers:

1. **Core Engine**
   - Inference
   - Embeddings
   - Model execution
   - Memory management

2. **Host Adapters (outside this repo or optional)**
   - Embedded host (linked into an app)
   - Daemon/service host (optional, thin wrapper)

3. **Consumers**
   - Shoots (via a provider adapter)
   - Standalone applications
   - OS-level tooling

The core engine has **no knowledge of Shoots**.

---

## Relationship to Shoots

- Shoots consumes Shoots.Engine via a **native provider adapter**
- Shoots performs orchestration, reasoning, confirmation, and UX
- Shoots.Engine performs execution only

Shoots.Engine must remain usable even if Shoots did not exist.

---

## Repository Rules (Non-Negotiable)

- No Shoots UI code
- No orchestration logic
- No provider selection logic
- No network servers in core
- No auto-downloading of models
- No implicit filesystem writes
- No prompt “helpfulness” in the engine

Violations of these rules are considered architectural bugs.

---

## Validation & Execution Policy

This repository follows the **Codex Operating Policy**.

Key points:
- Codex may only author patches
- All builds and tests run in CI
- No local execution by Codex
- CI logs are the single source of truth

See:
