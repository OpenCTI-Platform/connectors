# TDR: Generic deprecation and migration mechanism for connector configuration

## Overview

This document describes the introduction of a generic and centralized mechanism to deprecate and migrate configuration variables in the connectors SDK.

The change replaces ad-hoc, connector-specific migration logic with a declarative approach based on field metadata, executed in the `BaseConnectorSettings` validation pipeline.

---

## Context and previous state

Before this change, configuration deprecation was handled **manually and locally** in each connector, only when needed.

Typical patterns included:
- Custom `model_validator` implementations inside connectors
- Manual key renaming and value transformation
- Connector-specific warning messages
- Inconsistent behavior across connectors

This resulted in:
- Code duplication
- Inconsistent deprecation handling
- Higher maintenance cost
- No standard way to declare or document deprecated configuration keys

---

## Alternatives considered

### Alias-based validation with Pydantic

One considered approach was to rely on Pydantic features such as:
- `validation_alias`
- `validate_by_name`
- `AliasChoices`

This approach was simpler to implement and required less custom logic.

However, it had important limitations:
- No way to emit **explicit deprecation warnings**
- No distinction between legacy usage and canonical usage
- No support for value transformation during migration
- Limited control over namespace-level deprecation

Because deprecation would be silent, this approach was rejected.

---

## Goal

The goal of this change is to:

- Provide a **standard and reusable way** to deprecate configuration variables
- Preserve **backward compatibility** with existing configurations
- Make deprecated usage **explicit** via warnings
- Enforce a single canonical configuration schema validated by Pydantic

---

## Implemented solution

### Centralized migration in `BaseConnectorSettings`

A `model_validator(mode="wrap")` named `migrate_deprecation` is implemented in `BaseConnectorSettings`.

This validator:
- Runs during settings model validation, on the raw configuration dictionary
- Iterates over top-level settings namespaces and nested fields
- Migrates deprecated namespaces and variables based on field metadata
- Emits warnings when deprecated configuration is detected
- Returns a normalized configuration for validation

---

### Declarative deprecation via `DeprecatedField`

The SDK introduces `DeprecatedField`, a helper built on top of `pydantic.Field`, allowing deprecation metadata to be declared directly on fields.

Supported metadata includes:
- `deprecated`: deprecation flag or message (already present on pydantic.Field)
- `new_namespace`: destination namespace
- `new_namespaced_var`: destination variable name
- `new_value_factory`: optional value transformation function
- `removal_date`: optional removal deadline (ISO date)

This metadata is stored in the field definition and consumed automatically by the migration logic.

---

### Namespace and variable migration helpers

Migration behavior is implemented by two dedicated helpers in `connectors_sdk.settings.deprecations`:

- `migrate_deprecated_namespace`: migrates all keys from one namespace to another, with warning emission and conflict handling.
- `migrate_deprecated_variable`: migrates one variable to a new variable name and/or namespace, with optional value transformation.

Variable migration supports:
- Variable renaming
- Namespace changes
- Optional value transformation
- Conflict resolution when both old and new variables exist
- Warning emission

---

## Example usage

### Deprecated variable inside a configuration model

Preferred: using `DeprecatedField`:

```python
from pydantic import Field
from connectors_sdk import BaseConfigModel, DeprecatedField

class MyConfig(BaseConfigModel):
    old_var: int = DeprecatedField(
        deprecated="Use new_var instead",
        new_namespaced_var="new_var",
        new_value_factory=lambda x: x * 60,  # Optional transformation
        removal_date="2026-12-31",  # Optional informative removal deadline
    )
    new_var: int = Field(description="New variable")
```

Alternative: using `Deprecate` annotation metadata:

```python
from typing import Annotated
from pydantic import Field
from connectors_sdk import BaseConfigModel, Deprecate

class MyConfig(BaseConfigModel):
    old_var: Annotated[
        int,
        Deprecate(
            new_namespaced_var="new_var",
            new_value_factory=lambda x: x * 60,  # Optional transformation
            removal_date="2026-12-31",  # Optional informative removal deadline
        ),
    ]
    new_var: int = Field(description="New variable")
```

### Deprecated namespace at connector settings level

```python
from pydantic import Field
from connectors_sdk import BaseConnectorSettings, DeprecatedField

class ConnectorSettings(BaseConnectorSettings):
    old_namespace: MyConfig = DeprecatedField(
        deprecated="Use new_namespace instead",
        new_namespace="new_namespace",
        removal_date="2026-12-31",  # Optional informative removal deadline
    )
    new_namespace: MyConfig = Field(default_factory=MyConfig)
```

In this example:
- `old_var` is migrated to `new_var`, with an optional value transformation
- `old_namespace` is migrated to `new_namespace`

Deprecated usage triggers warnings
If both old and new settings are present, new settings take precedence

---

## Advantages

- Replaces manual, connector-specific deprecation logic
- Centralizes deprecation handling in the SDK
- Keeps configuration models clean and canonical
- Preserves backward compatibility
- Makes deprecated usage explicit via warnings
- Supports namespace-level and variable-level migrations
- Allows controlled value transformation during migration

---

## Disadvantages

- Deprecation rules must be explicitly declared via metadata
- Migration logic adds complexity to configuration loading
- Deprecated usage relies on warnings, which may be ignored
- Additional maintenance is required until deprecated keys are removed

---

## Summary

This change introduces a declarative, centralized framework for configuration deprecation in connectors.

By moving migration logic into the SDK and driving it through field metadata, it eliminates duplicated code, enforces a single validated configuration schema, and provides a clear and explicit deprecation path for users.

---

## Update (2026-03-13)

This TDR is amended to clarify the recommended public API for field deprecation declarations.

- `DeprecatedField` is the preferred and documented way to mark configuration fields as deprecated.
- `Deprecate` exists as a lower-level annotation and is available for direct `Annotated[...]` usage if preferred.
- `DeprecatedField` uses `Deprecate` metadata under the hood in `BaseConnectorSettings`, so both declaration syntaxes behave the same.
- `pydantic.SkipValidation` remains supported for backward compatibility, but it is no longer required when using `DeprecatedField`/`Deprecate`.

This update is a documentation clarification only (code examples have been updated). It does not change migration behavior.