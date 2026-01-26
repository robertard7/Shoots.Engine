# Error Model

## Overview
The error model defines deterministic, cross-language error reporting suitable for a C ABI. Errors are represented by explicit codes with optional metadata.

## Error Code Taxonomy
- **OK**: Successful operation with no error.
- **InvalidArgument**: Input is malformed, out of range, or violates contract.
- **InvalidState**: Operation is not permitted in the current lifecycle state.
- **OutOfMemory**: Allocation failed or requested memory exceeds limits.
- **ResourceUnavailable**: Required resource is unavailable or already in use.
- **Unsupported**: Requested operation or option is not supported by the build.
- **InternalFailure**: Engine encountered an unexpected internal condition.

## Severity
- **Recoverable**: The operation failed, but the engine instance remains valid.
- **Fatal**: The engine instance is no longer valid and must be destroyed.

## Machine-Readable vs Human-Readable
- Machine-readable output is the error code and severity.
- Human-readable output is an optional, separate message string.
- Human-readable messages must never alter control flow.

## Propagation Rules
- Every API call returns exactly one error code.
- When an error occurs, output buffers remain unmodified unless explicitly stated.
- Errors are deterministic for identical inputs and configuration.
- The engine performs no logging or side effects as part of error reporting.

## Ownership
- The host owns any memory used to receive error details.
- The engine must not allocate or retain error strings unless explicitly documented.
