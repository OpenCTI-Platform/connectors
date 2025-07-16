# TDR: Error and Warning Handling Tools

## Overview

This TDR explains the addition of a robust error and warning handling tools for developing the connectors using the SDK. The solution includes a dedicated subpackage, `exceptions`, which provides tools to handle validation warnings and errors effectively.

---

## Motivation

Connectors often require validation mechanisms to ensure data integrity processing and proper configuration.
Standardizing Custom Exceptions and Warning Handling is crucial for maintaining code quality and providing clear feedback to developers, users or other stakeholders.
Also, strict validation can lead to frequent errors that disrupt workflows. By introducing a permissive validation approach tool with warnings, developers can be informed of potential issues without halting execution. This improves flexibility while maintaining awareness of potential problems, especially with third-party data sources or evolving schemas. Moreover, the error and warning handling is essential as the connector runs independently from the stack in dedicated containers.

---

## Proposed Solution

We create an `exceptions` subpackage within the SDK. This subpackage includes Custom exceptions and warning handling tools to facilitate validation and error management in connectors.
These tools also enable developers to implement permissive validation logic while aggregating warnings for better debugging and monitoring.

---

## Advantages

- **Flexibility**: Allows connectors to handle unexpected or extra fields without raising errors.
- **Improved Debugging**: Provide easier analysis, especially when we do not have direct access to the running connectors.
- **Developer Awareness**: Provides detailed warnings about potential issues without disrupting execution.
- **Ease of Integration**: Tools are designed to integrate with Pydantic models.

---

## Disadvantages

- **Risk of Ignored Warnings**: Developers may overlook warnings, leading to unnoticed issues.
- **Risk of neglecting logging**: If not properly logged, info may be lost, making debugging difficult.

---

## Alternatives Considered

1. **Strict Validation**:
   - Enforcing strict validation rules with errors for all issues.
   - Rejected due to reduced flexibility and potential disruption in workflows.

2. **Custom Validation Logic**:
   - Implementing validation logic manually in each connector.
   - Rejected due to increased complexity and lack of standardization.

---

## References

- [Pydantic Documentation](https://docs.pydantic.dev) (consulted on 2025-06-11)
- [EuroPLOP 2004: Error Handling](https://www.eoinwoods.info/media/writing/EuroPLOP2004-error-handling.pdf) (consulted on 2025-06-11)
- [Devland API Design Guide: Errors](https://docs.devland.is/technical-overview/api-design-guide/errors) (consulted on 2025-06-11)
- [GeeksforGeeks: Error Handling in Programming](https://www.geeksforgeeks.org/error-handling-in-programming/) (consulted on 2025-06-11)

---
