# Inference API Contract

## Overview
The inference contract defines a deterministic request/response interface without prompt shaping or policy logic.

## Request Structure
- **Model identifier**: A stable identifier for a loaded model.
- **Input tokens**: A deterministic sequence of tokens supplied by the host.
- **Generation parameters**: Explicit, host-provided settings (e.g., max output tokens).
- **Execution limits**: Optional, explicit limits for time or steps.

## Response Structure
- **Output tokens**: The deterministic output token sequence.
- **Stop reason**: An explicit reason for termination (e.g., limit reached, end-of-sequence).
- **Usage metadata**: Explicit counts for input and output tokens.

## Determinism Guarantees
- Same input tokens, model identifier, and configuration must yield the same output tokens.
- No timestamps, randomness, or environment-derived behavior.

## Memory Ownership
- The host owns request buffers and input tokens.
- The engine owns only output buffers it explicitly allocates for the response.
- Ownership transfer must be explicit and documented per API call.

## Prohibited Behavior
- No prompt shaping or policy injection.
- No hidden defaults beyond explicitly supplied parameters.
- No streaming unless explicitly documented in the API surface.
