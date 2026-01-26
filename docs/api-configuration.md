# Configuration Surface

## Overview
The configuration surface defines all explicit options required to initialize the engine. Configuration is immutable after initialization.

## Configuration Options
- **model_root_path**: Host-provided path to model assets. No downloads or network access are permitted.
- **max_memory_bytes**: Hard limit on engine-owned memory allocations.
- **max_execution_steps**: Upper bound on deterministic execution steps per request.
- **allow_background_threads**: Explicit opt-in for background threads.
- **allow_filesystem_io**: Explicit opt-in for filesystem reads/writes.
- **allow_network_io**: Explicit opt-in for any networking behavior.

## Mutability Rules
- Configuration is provided at engine creation time.
- Configuration is immutable for the lifetime of the engine instance.
- Any change requires destroying and recreating the engine instance.

## Prohibited Defaults
- No implicit defaults beyond a zero/disabled state.
- All options must be explicitly provided by the host, even if set to disabled values.
