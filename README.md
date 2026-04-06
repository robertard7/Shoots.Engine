# Shoots.Engine

Shoots.Engine is a portable, embeddable AI execution core.

It is the lowest-level component in the Shoots stack and is responsible for running models and producing deterministic outputs.

Shoots.Engine does not orchestrate, does not expose public application contracts, and does not perform workflow logic.

Think execution core, not system.

Purpose

Shoots.Engine exists to provide:

A local model execution layer
A deterministic inference runtime
A portable AI core that can be embedded anywhere

It is designed to be:

Embedded directly into applications
Hosted optionally by a runtime layer
Shipped as part of operating systems or standalone software
Fully usable without any Shoots-specific components
Scope (Enforced)

Shoots.Engine is responsible for:

Local model loading and unloading
Model registry access (local only, no auto-fetching)
Inference execution (prompt → tokens/output)
Embedding generation
Session/context primitives (context windows, buffers)
Memory and lifecycle control of model execution
Deterministic request → response behavior
Low-level runtime error reporting (engine-level failures only)
Local backend adapters required to execute models
Out of Scope (Non-Negotiable)

Shoots.Engine must NOT contain:

UI code
Chatbot/product behavior
Agent logic or reasoning systems
Workflow or orchestration logic
Taskboards, lanes, or execution policy
Provider ABI or request/response envelope definitions
Queueing, polling, or lifecycle orchestration
Network services in core
Model downloading or remote fetching
Implicit filesystem writes
“Helpful” prompt modification or hidden behavior

If it is not required to execute a model deterministically, it does not belong here.

Design Principles
1. Library-first

Shoots.Engine must work fully when embedded into another system.
No host is required for correct operation.

2. Deterministic

Given:

the same model
the same input
the same parameters

The output must be reproducible.

3. Explicit Control
No hidden defaults
No implicit behavior
All execution parameters must be visible and controllable
4. No Side Effects by Default

Shoots.Engine does nothing unless explicitly told to:

No networking
No background threads unless explicitly started
No filesystem writes unless explicitly requested
5. Replaceable Backends

The engine may support multiple local execution backends, but:

Backend selection must be explicit
No hidden fallback behavior
No provider-specific logic inside the engine
6. Stable Core Interface

Shoots.Engine exposes a stable interface for:

model execution
embeddings
session/context control

Higher-level contracts belong to Shoots.Provider.

Architecture Position

Shoots.Engine sits at the bottom of the stack:

Application / UI (RAMY, etc.)
        ↓
Shoots.Provider (ABI / contract)
        ↓
Shoots.Runtime (lifecycle / orchestration)
        ↓
Shoots.Engine (execution core)
        ↓
Local models

Shoots.Engine does not know about any layer above it.

Relationship to Shoots
Shoots.Provider consumes Shoots.Engine through a controlled adapter
Shoots.Runtime may host and coordinate Engine execution
Shoots (or RAMY) performs orchestration, reasoning, and UX

Shoots.Engine performs execution only

Repository Rules (Strict)

The following are considered architectural violations:

Adding orchestration or workflow logic
Adding provider-level contracts
Adding UI or agent logic
Introducing hidden behavior or side effects
Coupling Engine to any specific application
Validation Policy
All changes must preserve deterministic behavior
All model execution paths must be testable
Failures must be explicit and structured
No silent fallbacks

Shoots.Engine must remain:

predictable, portable, and controlled

Guiding Principle

Shoots.Engine is not smart.

It does not decide what to do.

It does not help.

It does not adapt.

It executes.

Everything above it is responsible for intelligence.

Mental Model

Think:

SQLite for AI execution

Not:

a service
a chatbot
a framework

Just a reliable, embeddable execution core
