# Host Responsibility Contract

This document defines what the host must provide and guarantee when embedding
Shoots.Engine. These requirements are explicit and non-ambiguous.

## Memory Ownership

- The host owns all memory it allocates and passes to the engine.
- The engine owns all memory it allocates and returns to the host.
- The host must release engine-owned buffers using `shoots_engine_free`.
- The host must not free engine-owned buffers directly.

## Lifecycle Ordering

- The host must create an engine with `shoots_engine_create` before using any API.
- The host must destroy the engine with `shoots_engine_destroy` before discarding
  the engine handle.
- The host must unload all models before destroying the engine.
- The host must not reuse handles after destruction.

## Threading Guarantees

- The engine performs no background work unless explicitly enabled via configuration.
- The host must not assume any internal threading without explicit configuration.
- The host is responsible for external synchronization when calling the engine
  from multiple threads.

## IO Permissions

- The engine obeys the configuration flags for filesystem, networking, and
  background threading.
- The host must set `allow_filesystem_io` and `allow_network_io` explicitly.
- The host must not assume any implicit IO beyond what is configured.

## Engine Non-Responsibilities

The engine will never:

- Start background threads unless explicitly allowed.
- Perform filesystem IO unless explicitly allowed.
- Perform network IO unless explicitly allowed.
- Act as a service, daemon, or long-running host-controlled process.
- Download models or data automatically.
