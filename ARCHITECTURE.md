# Shoots.Engine – Architecture

Shoots.Engine is a **library-first AI runtime**.

## Layering

1. Core Engine
   - Inference
   - Embeddings
   - Model execution
   - Memory and lifecycle

2. Hosts (outside core)
   - Embedded host (in-process)
   - Optional daemon/service host

3. Consumers
   - Shoots (via provider adapter)
   - Standalone applications

## Non-Goals

The core engine must never:
- Start network listeners
- Choose providers
- Perform orchestration
- Apply prompt policy
- Manage UI or workflows

## Determinism Contract

- Same inputs + same model = same outputs
- No timestamps
- No randomness unless explicitly configured
- All behavior must be testable and replayable

This file is normative.
