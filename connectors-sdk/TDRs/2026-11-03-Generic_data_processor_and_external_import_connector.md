# TDR: Generic data processor and external import connector

## Overview
This document describes how `BaseDataProcessor` and `ExternalImportConnector` become generic over the connector's settings and state types, so that a type checker knows `self.settings.<section>` and `self.state.<checkpoint>` in a data processor. It also introduces one settings base class per connector type (`Base<Type>ConnectorSettings`).

Runtime behaviour does not change for any existing connector. The change is static typing only.

---

## Motivation

Data processors were typed with the SDK base classes: `settings` was a `BaseConnectorSettings` and `state` an `ExternalImportConnectorState`. A connector's own settings section (`self.settings.my_connector.api_url`) or state checkpoint (`self.state.last_cursor`) was therefore unknown to the type checker.

Connectors on `master` work around this in two ways:

- 6 of them redeclare attributes in the processor (`settings: ConnectorSettings`, `state: ConnectorState`): 4 redeclare both (`enisa-euvd`, `honeylabs`, `rosti`, `vulnerability-lookup`) and 2 only `state` (`crowdstrike-incidents`, `orkl`). This is an unchecked narrowing of a mutable attribute: pyright reports it, and mypy accepts it only because the `mutable-override` error code is off by default. With the new bound, a redeclared `settings` that does not inherit the per-type base becomes an `assignment` error under mypy.
- 4 of them (`crowdstrike-incidents`, `orkl`, `shadowserver`, `zerofox-alerts`) add a `# type: ignore[attr-defined]` where they read their settings section.

The SDK has the same problem on its side: `ExternalImportConnector.start()` carried a `# type: ignore` on `self.settings.connector.duration_period`, because `BaseConnectorSettings.connector` is a `_BaseConnectorConfig`, which has no `duration_period`.

---

## Proposed Solution

`BaseDataProcessor` and `ExternalImportConnector` are `Generic[SettingsT, StateT]`:

- `SettingsT` is bound to `BaseExternalImportConnectorSettings`, `StateT` to `ExternalImportConnectorState`.
- Both have PEP 696 defaults (those same base classes), so an unparameterized `BaseDataProcessor` keeps working and type-checks under strict mode.
- The SDK supports Python 3.11, so the type variables are created with `typing_extensions.TypeVar` (PEP 696 defaults) and not with PEP 695 syntax. `typing_extensions` is now a declared dependency of `connectors-sdk`.
- `settings`, `state` and `inject_dependencies()` use these type variables. `ExternalImportConnector` takes `data_processors: list[BaseDataProcessor[SettingsT, StateT]]`, so the type checker infers its parameters from the arguments.

A new settings base class exists per connector type: `BaseExternalImportConnectorSettings`, `BaseInternalEnrichmentConnectorSettings`, `BaseStreamConnectorSettings`, `BaseInternalExportFileConnectorSettings` and `BaseInternalImportFileConnectorSettings`. Each one narrows `connector` to the matching `Base<Type>ConnectorConfig`. This is what makes the `SettingsT` bound useful: a bound on `BaseConnectorSettings` would still expose `connector` as `_BaseConnectorConfig`, and the `duration_period` ignore could not be removed. It is now removed.

Usage:

```python
# Tells the type checker which settings and state this processor uses.
class ReportsProcessor(BaseDataProcessor[ConnectorSettings, ConnectorState]):
    work_name = "Reports import"

    def collect(self) -> list[TemplateReport]:
        # self.settings is a ConnectorSettings, self.state a ConnectorState
        api_key = self.settings.template.api_key.get_secret_value()
        ...
```

The external-import template processors use this form, without any redeclared attribute.

When `state` is omitted, `ExternalImportConnector` creates a default `ExternalImportConnectorState`, typed with a `cast("StateT", ...)`.

The typing behaviour is covered by `tests/type_checks/check_external_import_generics.py`. It is checked by the strict `mypy .` run of the SDK test session, and is never collected by pytest. Positive cases use `assert_type`. Rejections are proved with `# type: ignore[<code>]`: with `warn_unused_ignores`, a rejection that is lost makes `mypy` fail. Runtime tests cover parameterized subclasses.

The VC305 check of `connector-linter` is relaxed to accept the per-type base classes in addition to `BaseConnectorSettings`, otherwise every connector built from the templates would fail it. VC303 and VC306 are taught the per-type settings names as well.

---

## Advantages

- `self.settings.<section>` and `self.state.<checkpoint>` are checked in a parameterized processor, with IDE completion, and without redeclared attributes or `type: ignore`.
- No unchecked narrowing of a mutable attribute is left in processors.
- The `# type: ignore` in `start()` is gone: `settings.connector.duration_period` is typed.
- Runtime is unchanged for every existing connector. Unparameterized processors keep working thanks to the PEP 696 defaults.
- The per-type settings base classes are reusable by the other connector types.

---

## Disadvantages

- **Invariance.** `settings` and `state` are writable attributes, so the type variables are invariant. All the processors of a connector must declare the same `[ConnectorSettings, ConnectorState]`, the same as the connector. A list mixing parameterized and bare processors is rejected by mypy (`list-item`), and a processor parameterized with other settings is rejected too (`misc`). Parameterizing a processor with settings that do not meet the bound, such as `BaseDataProcessor[LegacySettings, MyState]`, is rejected at the class definition (`type-var`). Passing `ExternalImportConnector` a `state` that is not the processors' state type is rejected as well (`misc`).
- **The settings must inherit the per-type base.** Settings that inherit only `BaseConnectorSettings` are rejected by `ExternalImportConnector` (`type-var`). In a bare processor, a redeclared `settings:` of such a class is an `assignment` error. Type-checking a connector therefore requires its settings to inherit `BaseExternalImportConnectorSettings`. A bare processor that redeclares attributes with settings inheriting the new base still type-checks: the connector is inferred with the default parameters and the settings are upcast.
- **The `cast` for the default state.** When `state` is omitted, the type checker cannot link `StateT` to the default instance, hence the `cast`. It is unsound for custom states: if the processors are parameterized with a custom state and no `state` is passed, mypy infers the custom type while the runtime object is an `ExternalImportConnectorState`. Using `@overload` instead would fix this, but would add stub lines against the 100% coverage requirement of the SDK; this trade-off was accepted.
- **No CI job type-checks connectors yet.** Until one exists (separate issue), the value on the connector side is IDE-only.
- **Migration is a follow-up.** Existing connectors are not migrated here: it is done one connector at a time. Meanwhile, those whose settings inherit only `BaseConnectorSettings` would get the static errors above if they were type-checked.
- The SDK now depends on `typing_extensions`.

---

## Alternatives Considered

1. **A `Protocol` as the `SettingsT` bound**, exposing `connector.duration_period`.

    **Rejected**. It cannot be combined with the `BaseConnectorSettings` bound, because Python has no intersection types.

2. **An `isinstance` check in `start()`**.

    **Rejected**. It is a runtime-only check: the type checker, and so the IDE, still does not know the settings types in processors.

3. **Covariant type variables**.

    **Rejected**. `settings` and `state` are writable attributes (`inject_dependencies()` assigns them, and processors write state checkpoints), so covariance is unsound.

4. **Keep the redeclarations in each processor**.

    **Rejected**. It is an unchecked narrowing of a mutable attribute, reported by pyright and hidden in mypy only by a disabled error code. Each processor repeats it, and it does not help the connector class.

---

## References

- Issue: [#8184](https://github.com/OpenCTI-Platform/connectors/issues/8184)
- Related TDR: [Typing and validation of configurations with Pydantic Settings](https://github.com/OpenCTI-Platform/connectors/blob/master/connectors-sdk/TDRs/2025-10-01-Typing_and_validation_of_configurations_with_Pydantic_Settings.md)
- Related TDR: [Typing and validation of connector's state with Pydantic](https://github.com/OpenCTI-Platform/connectors/blob/master/connectors-sdk/TDRs/2026-04-14-Typing_and_validation_of_connector_state_with_pydantic.md)
- [PEP 696 – Type defaults for type parameters](https://peps.python.org/pep-0696/)
- [typing_extensions documentation](https://typing-extensions.readthedocs.io/en/latest/)

---
