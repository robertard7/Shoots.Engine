# Engine Capability Declaration

This document defines the machine-readable capability flags for a Shoots.Engine
build. These flags are immutable after `shoots_engine_create`.

## Capability Flags

Each capability is represented by a fixed flag with a boolean value.

- `threads`: background threading permitted only when `allow_background_threads` is set.
- `filesystem_io`: filesystem IO permitted only when `allow_filesystem_io` is set.
- `network_io`: network IO permitted only when `allow_network_io` is set.

## Immutability

- Capability flags are derived solely from the configuration used at
  `shoots_engine_create`.
- Capability flags do not change for the lifetime of the engine handle.
- The engine will not enable capabilities that were not explicitly allowed.
