# Engine Lifecycle Contract

## Overview
The engine lifecycle defines how a host creates, uses, and destroys an engine instance deterministically. The engine never self-starts and never assumes global state.

## Lifecycle States
- **Uninitialized**: No engine instance exists.
- **Initialized**: An engine instance exists and is ready to accept requests.
- **Shut down**: The engine instance is destroyed and its handle is invalid.

## Creation Semantics
- The host explicitly creates a new engine instance.
- Creation allocates only engine-owned state required to represent the instance.
- Creation must be deterministic for identical configuration inputs.

## Shutdown Semantics
- The host explicitly destroys the engine instance.
- Destruction releases all engine-owned resources.
- After shutdown, the handle is invalid and must not be reused.
- A second destroy call returns a deterministic invalid-state error.

## Post-Destroy Call Matrix
- **Allowed**: None (all calls after destroy return invalid-state errors).
- **Forbidden**: All engine API calls, including destroy and free, must return deterministic invalid-state errors.

## Invalid Handle Behavior
- **Null handle**: Deterministic invalid-argument error.
- **Invalid magic**: Deterministic invalid-argument error.
- **Destroyed handle**: Deterministic invalid-state error.

## Ownership Rules
- The host owns the lifecycle and is responsible for calling create and destroy.
- The engine owns only resources it explicitly allocates during its lifetime.
- The engine must never claim ownership of host-managed buffers unless explicitly documented.

## Forbidden Behavior
- No background threads unless explicitly enabled in configuration.
- No filesystem I/O unless explicitly enabled in configuration.
- No networking unless explicitly enabled in configuration.
- No implicit global state or process-wide singletons.
