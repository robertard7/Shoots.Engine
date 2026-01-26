# Embedding API Contract

## Overview
The embedding contract defines deterministic vector generation as a first-class operation.

## Request Structure
- **Model identifier**: A stable identifier for a loaded embedding-capable model.
- **Input tokens**: A deterministic sequence of tokens supplied by the host.
- **Execution limits**: Optional, explicit limits for time or steps.

## Response Structure
- **Embedding vector**: A fixed-length vector of numeric values.
- **Dimensionality**: The fixed dimensionality for the selected model.
- **Usage metadata**: Explicit counts for input tokens.

## Guarantees
- **Dimensionality**: The vector length is fixed per model and documented by the engine.
- **Ordering**: Vector element ordering is stable and deterministic.
- **Stability**: Same input tokens, model identifier, and configuration yield the same vector.

## Memory Ownership
- The host owns request buffers and input tokens.
- The engine owns only output buffers it explicitly allocates for the response.
- Ownership transfer must be explicit and documented per API call.

## Prohibited Behavior
- No implicit normalization or post-processing.
- No hidden defaults beyond explicitly supplied parameters.
