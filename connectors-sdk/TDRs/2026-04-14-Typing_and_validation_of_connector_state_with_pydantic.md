# TDR: Typing and validation of connector's state with Pydantic

<br>

## Overview

This document describes the introduction of `ConnectorStateManager`, a Pydantic-based class added to the `connectors-sdk` under the `state_manager` module.  
It provides a standardized, typed, and validated interface for loading and saving a connector's state to and from the OpenCTI platform, replacing the ad-hoc, per-connector state management patterns that currently exist across the repository.

This work is a first step in building the `BaseConnector` module suite — a set of standardized SDK components designed to reduce the boilerplate each connector developer has to write and maintain.

<br>

## Motivation

### The current state of state management

Today, every connector in the repository manages its own state independently. The typical pattern looks like this:

```python
class Connector:
    def run(self):
        # At run's  start:
        state = self.helper.get_state() or {}
        last_run = state.get("last_run")
        if last_run is not None:
            last_run = datetime.fromisoformat(last_run)

        # Execute any business logic specific to the connector...

        # At the end of the run:
        self.helper.set_state({"last_run": datetime.now(tz=timezone.utc).isoformat()})
        self.helper.force_ping()
```

While simple in isolation, this pattern is repeated — with variations — across 200+ connectors. The consequences are:

1. **Massive code duplication**. Every connector reimplements the same load/save cycle, often with subtle differences in key names, serialization format (timestamps vs. ISO strings), or error handling.

2. **No typing or validation**. State is a raw `dict`. There is no guarantee that a value is present, that it has the correct type, or that it is valid before being used. Bugs surface at runtime, often silently (e.g. `None` passed to a function expecting a `datetime`).

3. **Inconsistent serialization**. Some connectors store datetimes as Unix timestamps, others as ISO strings, others as formatted strings. There is no enforced contract, making cross-connector reasoning and debugging unnecessarily difficult.

4. **No shared baseline**. There is no common field that all connectors are guaranteed to track (e.g. `last_run`), even though virtually every connector needs it.

<br>

## Proposed Solution

### The `ConnectorStateManager` class

`ConnectorStateManager` is a non-abstract Pydantic `BaseModel` that wraps the `OpenCTIConnectorHelper` state API. It can be used directly or subclassed to define connector-specific state fields.

```python
# connectors-sdk/connectors_sdk/state_manager/state_manager.py

class ConnectorStateManager(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
    )

    last_run: datetime | None = Field(default=None)

    def __init__(self, helper: OpenCTIConnectorHelper): ...

    def load(self) -> None:
        """Overwrite instance's fields with the connector's state stored on OpenCTI."""

    def save(self) -> None:
        """Save instance's fields as connector's state on OpenCTI."""
```

<br>

### Key design decisions

| Decision | Rationale |
| --- | --- |
| Inherits from `pydantic.BaseModel` | Consistent with `BaseConnectorSettings`; provides typing, validation, and JSON serialization for free. |
| `extra="allow"` | Allows connectors to store additional state fields not declared in the base class, without breaking the model. |
| `validate_assignment=True` | Ensures that any field update (via `setattr`) is validated immediately, not only at construction time. |
| `last_run: datetime \| None` | Provides a common baseline field that virtually every connector needs, pre-typed as `datetime`. |
| `load()` | Dynamically populates declared fields from the raw `dict` returned by OpenCTI, with Pydantic validation applied on assignment. |
| `save()` uses `model_dump(mode="json")` | Serializes all fields to JSON-safe types automatically, removing the need for manual type
conversions (e.g. converting a `datetime` to a string). |
| Not abstract | Can be used as-is for simple connectors; subclassed for connectors with richer state needs. |

<br>

### Usage examples

#### Simple usage (no subclassing needed):

```python
state_manager = ConnectorStateManager(helper=self.helper)
state_manager.load()

if state_manager.last_run:
    self.helper.connector_logger.info("Last run:", {"last_run": state_manager.last_run})

state_manager.last_run = datetime.now(tz=timezone.utc)
state_manager.save()
```

#### Subclassed with connector-specific fields:

```python
class CustomConnectorState(ConnectorStateManager):
    last_cursor: str | None = Field(default=None)
    last_page: int = Field(default=0)

state_manager = CustomConnectorState(helper=self.helper)
state_manager.load()
state_manager.last_cursor = "abc123"
state_manager.last_page = 5
state_manager.save()
```

<br>

### Module location

Consistent with the SDK folder structure agreed in the architecture decisions, the module lives at:

```plaintext
connectors-sdk/
└── connectors_sdk/
    └── state_manager/
        ├── __init__.py
        └── state_manager.py
```

The `state_manager` module has no dependency on other SDK modules (`settings`, `models`, etc) and can therefore be adopted by any connector, independently of the broader `BaseConnector` usage.

<br>

## Advantages

- **Typed state with early validation**. Fields are declared with Python type annotations. Pydantic validates values at assignment time (`validate_assignment=True`), surfacing type errors before they can corrupt state on OpenCTI.

- **Consistent JSON serialization**. `model_dump(mode="json")` ensures that all field types (including `datetime`) are serialized to JSON-safe representations, eliminating the inconsistency between types and/or formats across connectors.

- **Common baseline field**. `last_run: datetime | None` is provided out of the box, with the correct type, for all connectors.

- **Easy to extend**. Adding connector-specific state fields is a single-line declaration in a subclass. No changes to the loading or saving logic are required.

- **Consistent with existing SDK patterns**. Reuses Pydantic, the same library already used for `BaseConnectorSettings` or OCTI models, keeping the SDK's dependency surface minimal and the developer experience uniform.

- **Independent of other SDK modules**. Can be adopted incrementally, by any connector type, without waiting for the full `BaseExternalImportConnector` to be available.

<br>

## Disadvantages

- **Pydantic dependency**. `ConnectorStateManager` inherits Pydantic's lifecycle and upgrade constraints. This is an accepted trade-off, consistent with the rest of the SDK.

- **`extra="allow"` may mask errors**. Undeclared fields are silently accepted. A typo in a field name when subclassing would not raise an error — the value would be stored as an extra field rather than populating the intended declared field. This is mitigated by `validate_assignment=True` on declared fields and is a deliberate flexibility trade-off for backward compatibility.

- **`save()` only persists declared fields**. Extra fields (those not explicitly declared in the model) are not persisted. This is intentional to avoid leaking internal attributes, but connector developers must declare every field they want to save.

- **Learning curve**. Developers unfamiliar with Pydantic will need to understand the model declaration pattern. This is the same trade-off already accepted for `BaseConnectorSettings` or OCTI models.

<br>

## Alternatives Considered

1. **Keep the current ad-hoc pattern (do nothing)**

    Each connector continues to call `helper.get_state()` / `helper.set_state()` directly, with its own serialization logic.

    **Rejected**. This is the root cause of the inconsistency, duplication, and bugs described in the "Motivation" section. The longer this is deferred, the more expensive any future cross-cutting change becomes.

2. **A plain `dataclass` or `TypedDict`**

    Use a `dataclass` or `TypedDict` to type the state, with manual serialization.

    **Rejected**. Provides typing but no runtime validation, no automatic JSON serialization, and no `validate_assignment` semantics. It would also diverge from the Pydantic-first approach already established in the SDK.

3. **A generic `StateManager[T]` with a separate `BaseState` model**

    Define a generic container class `StateManager[T: BaseModel]` that wraps a separate state model `T`, with `load() -> T` and `save(state: T) -> None` as its interface.

    **Considered**. This was one of the designs explored for this feature. It was ultimately set aside in favour of a simpler approach: having the manager _be_ the state (by inheriting from `BaseModel` directly) reduces the number of objects a connector developer must instantiate and reason about, and avoids the ergonomic overhead of passing a state object in and out of the manager on every call. The simpler design is easier to use correctly.

4. **Abstract base class**

    Make `ConnectorStateManager` abstract, forcing subclassing for every use.

    **Rejected**. Many connectors only need `last_run`. Forcing them to subclass adds friction with no benefit. The non-abstract design follows the principle of opinionated defaults, override hooks where needed.

<br>

## References

- Related TDR: [Typing and validation of configurations with Pydantic Settings](https://github.com/OpenCTI-Platform/connectors/blob/master/connectors-sdk/TDRs/2025-10-01-Typing_and_validation_of_configurations_with_Pydantic_Settings.md)
- [Pydantic BaseModel documentation](https://docs.pydantic.dev/latest/concepts/models/)
- [Pydantic serialization (JSON mode)](https://docs.pydantic.dev/latest/concepts/serialization/#json-mode)
