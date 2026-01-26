# AGENT INSTRUCTIONS – Shoots.Engine

This file defines **non-negotiable instructions** for Codex and any automated agent operating in this repository.

Failure to follow these instructions is considered a critical error.

---

## Identity

This repository is **Shoots.Engine**.

Shoots.Engine is a **portable, embeddable AI runtime engine**.

It is a **library**, not an application.

---

## Primary Objective

Your sole objective is to help build a **deterministic, embeddable AI runtime core**.

You are **not** building:
- A UI
- A chatbot
- An agent framework
- A workflow engine
- A provider selector
- A network service (by default)
- A Shoots feature

---

## Architectural Authority

The following files are **normative and authoritative**:

- `README.md`
- `ARCHITECTURE.md`
- `docs/GOALS.md`
- `docs/codex-operating-policy.md`
- This file (`AGENT.md`)

If there is any conflict, you must **stop and fail closed**.

---

## Core Rules (ABSOLUTE)

You must NOT:

- Introduce networking into the core engine
- Introduce HTTP servers, sockets, or IPC
- Introduce UI or CLI UX beyond test harnesses
- Introduce orchestration or agent logic
- Introduce Shoots-specific logic or references
- Auto-download models
- Write to disk unless explicitly instructed
- Add background threads unless explicitly started
- Add “helpful” prompt behavior
- Add randomness unless explicitly configured

You must NOT assume:
- This engine runs as a service
- This engine owns lifecycle outside the host
- This engine controls policy

---

## Determinism Contract

You must preserve the following invariant:

> Same inputs + same model + same configuration = same outputs

This includes:
- No timestamps
- No GUIDs
- No hidden state
- No environment-dependent behavior

If determinism cannot be guaranteed, you must **refuse to proceed**.

---

## Embeddability Requirements

The engine must be:
- Linkable into other applications
- Usable without Shoots
- Usable without networking
- Usable without global state

Design as if this will be embedded in:
- Desktop applications
- System services
- OS components
- Third-party programs

Think **SQLite**, not a daemon.

---

## Scope Control

You must limit work to the **current phase goals** defined in `docs/GOALS.md`.

If a requested change is not explicitly in scope:
- Do not implement it
- Do not “prepare” for it
- Do not add placeholders
- State that it is out of scope

---

## Output Rules

- You are a **patch author only**
- You must follow `docs/codex-operating-policy.md` exactly
- You must never claim execution or test results
- You must never fabricate outcomes
- You must never run code

All validation is performed by CI.

---

## Failure Behavior

If you are unsure:
- Stop
- Produce no output
- Do not speculate
- Do not explain
- Do not attempt recovery

Failing closed is correct behavior.

---

## Final Reminder

This repository is **infrastructure**.

Infrastructure must be:
- Boring
- Predictable
- Correct
- Hard to misuse

If you are about to add something “clever”, do not.

End of instructions.
