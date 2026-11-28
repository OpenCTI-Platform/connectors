# Internal Enrichment Connector Specifications

**Document:** 03-internal-enrichment-specifications.md
**Connector Type:** `INTERNAL_ENRICHMENT`

## Table of Contents

- [Overview](#overview)
- [Connector Architecture](#connector-architecture)
- [The Enrichment Message](#the-enrichment-message)
- [Message Handling](#message-handling)
- [Entity Scope](#entity-scope)
- [TLP Check](#tlp-check)
- [Playbook Compatibility](#playbook-compatibility)
- [Building the Enrichment Result](#building-the-enrichment-result)
- [Errors and Logging](#errors-and-logging)
- [Testing](#testing)
- [Best Practices](#best-practices)
- [Complete Example](#complete-example)
- [Legacy Connectors](#legacy-connectors)

---

## Overview

Internal Enrichment connectors enrich entities that already exist in OpenCTI by adding additional context, relationships, and metadata from external sources.

### Purpose

- Enrich observables (IPs, domains, hashes, etc.)
- Add context to indicators, vulnerabilities, and other entities
- Create relationships between enriched entities and new information
- Support automated enrichment workflows (playbooks)

### Key Characteristics

- **Event-driven**: Triggered manually, automatically when an entity is created (`CONNECTOR_AUTO`), or by a playbook step
- **Push-based**: OpenCTI pushes entities to the connector
- **Stateless**: Each enrichment request is independent
- **Scope-based**: Only processes configured entity types

### Use Cases

- IP/domain reputation enrichment
- File hash analysis
- Vulnerability information lookup
- Geolocation enrichment
- WHOIS data enrichment
- Threat actor attribution

---

## Connector Architecture

Internal enrichment connectors are built on the `InternalEnrichmentConnector` base class of
`connectors-sdk`. **You no longer write the scope check, the TLP check, the playbook handling or
the bundle sending yourself**: the base class does all of that. Your job is to describe how to
fetch data about an entity and how to convert it to STIX.

An internal enrichment connector is made of three pieces:

| Piece                       | Base class (from `connectors-sdk`)              | Responsibility                                                         |
| --------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------- |
| `ConnectorSettings`         | `BaseInternalEnrichmentConnectorSettings`       | Validate configuration (env vars / `config.yml`) with Pydantic         |
| One or more `...Processor`  | `BaseEnrichmentProcessor[ConnectorSettings]`    | Fetch (`collect`) and convert (`transform`) data about one or more entity types |
| The connector itself        | `InternalEnrichmentConnector`                   | Listen to messages, check scope and TLP, pick the processor, send the bundle |

Each message is passed to the processor as an `EnrichmentMessage`, a read-only view of the
entity to enrich (see [The Enrichment Message](#the-enrichment-message)).

> [!TIP]
> A ready-to-use, fully documented template implementing this architecture is available at
> [templates/internal-enrichment](../templates/internal-enrichment): settings, an example
> processor in `src/connector/enrichment_processors/`, an API client and tests. Copy it as a
> starting point (see the [CONTRIBUTING guidelines](../CONTRIBUTING.md)).
> [internal-enrichment/spur-enrichment](../internal-enrichment/spur-enrichment) is a complete
> connector built on this architecture.

The design decisions behind the base class are recorded in the
[TDR](../connectors-sdk/TDRs/2026-10-05-Internal_enrichment_connector_base.md).

### The enrichment processor: `collect()` + `transform()`

A **processor** enriches one or more entity types from the external source. You subclass
`BaseEnrichmentProcessor`, declare the entity types it handles, and implement two methods (plus an
optional `post_init()`). In the template, processors live in `src/connector/enrichment_processors/`,
one module per processor:

```python
from typing import Any

from connector.settings import ConnectorSettings
from connectors_sdk import (
    ApiClientError,
    ApiNotFoundError,
    BaseEnrichmentProcessor,
    EnrichmentMessage,
)
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import (
    AutonomousSystem,
    IPV4Address,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import RelationshipType
from my_client import MyClient  # built on connectors_sdk.BaseClientApi


# Tells the type checker which settings this processor uses.
class IPv4Processor(BaseEnrichmentProcessor[ConnectorSettings]):
    """Enrich an IPv4 address with the My Source API."""

    # OpenCTI entity types, compared case-insensitively with the entity to enrich
    handled_entity_types = frozenset({"IPv4-Addr"})

    def post_init(self) -> None:
        """Build the API client, the author and the marking once.

        `settings` and `logger` are available here: the base connector injects the
        settings before calling this hook.
        """
        self.client = MyClient(
            api_key=self.settings.my_source.api_key.get_secret_value()
        )
        self.author = OrganizationAuthor(name="My Source")
        self.tlp_marking = TLPMarking(level=self.settings.my_source.tlp_level)

    def collect(self, message: EnrichmentMessage) -> dict | None:
        """Fetch raw data about the entity. No STIX conversion here."""
        try:
            return self.client.get_ip(message.stix_entity.value)
        except ApiNotFoundError:
            return None  # The source does not know the IP: not an error
        except ApiClientError as err:
            raise DataRetrievalError("Failed to fetch the IP report") from err

    def transform(self, data: dict | None, message: EnrichmentMessage) -> list[Any]:
        """Convert raw data into STIX objects. No network call here."""
        if not data:
            return []  # Nothing to add: not an error
        # Same value, so same id as the entity received: OpenCTI merges the two
        ip = IPV4Address(value=message.stix_entity.value, score=data["score"])
        autonomous_system = AutonomousSystem(
            number=data["asn"],
            author=self.author,
            markings=[self.tlp_marking],
        )
        relationship = Relationship(
            type=RelationshipType.BELONGS_TO,
            source=ip,
            target=autonomous_system,
            author=self.author,
            markings=[self.tlp_marking],
        )
        return [self.author, self.tlp_marking, ip, autonomous_system, relationship]
```

The brackets after `BaseEnrichmentProcessor` tell the type checker which settings class the
connector uses, so `self.settings` is typed without redeclaring it. Every processor of a connector
must declare the same settings class as the connector.

For each message, the base class calls `process()`, which runs:

```text
objects = transform(data=collect(message), message=message)
```

- `collect(message)` fetches raw data about the entity from the external source.
- `transform(data, message)` converts it into STIX / `connectors-sdk` model objects, and returns
  them as a list. Generators are not supported: one message gives one bundle.
- The processor never sends anything: the base class builds the bundle from the objects returned.

A processor is created once and handles every message: keep everything that depends on the
current message in local variables, never in attributes of `self`.

### Wiring it together: `main.py`

The entry point loads the settings, builds the list of processors, and starts the connector. No
`OpenCTIConnectorHelper`, no `helper.listen()`: the base class creates the helper and listens.

```python
import traceback

from connector import ConnectorSettings
from connector.enrichment_processors import IPv4Processor
from connectors_sdk import BaseEnrichmentProcessor, InternalEnrichmentConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()

        enrichment_processors: list[BaseEnrichmentProcessor[ConnectorSettings]] = [
            IPv4Processor(),
        ]

        connector = InternalEnrichmentConnector(
            settings=settings,
            enrichment_processors=enrichment_processors,
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
```

`InternalEnrichmentConnector` checks the configuration when it is created, before connecting to
OpenCTI:

- `settings.connector` must be a `BaseInternalEnrichmentConnectorConfig` (or subclass), otherwise
  `TypeError`.
- At least one processor is required, otherwise `ValueError`.
- Every entity type of `connector.scope` must be declared by a processor, otherwise
  `ConfigValidationError`.
- A processor class that can be instantiated without `handled_entity_types` raises `TypeError`
  as soon as the class is defined.

### Settings

The settings extend `BaseInternalEnrichmentConnectorSettings`, which narrows `connector` to
`BaseInternalEnrichmentConnectorConfig`:

```python
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseInternalEnrichmentConnectorConfig,
    BaseInternalEnrichmentConnectorSettings,
    ListFromString,
)
from pydantic import Field, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    id: str = Field(description="The UUID of the connector.", default="<uuid4>")
    name: str = Field(description="The name of the connector.", default="My Source")
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["IPv4-Addr"],
    )


class MySourceConfig(BaseConfigModel):
    api_key: SecretStr = Field(description="My Source API key.")
    tlp_level: Literal["clear", "green", "amber", "amber+strict", "red"] = Field(
        description="TLP marking applied to the objects created by the connector.",
        default="amber",
    )


class ConnectorSettings(BaseInternalEnrichmentConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    my_source: MySourceConfig = Field(default_factory=MySourceConfig)
```

`BaseInternalEnrichmentConnectorConfig` provides:

| Setting                       | Default  | Purpose                                                                 |
| ----------------------------- | -------- | ----------------------------------------------------------------------- |
| `connector.scope`             | -        | Entity types the connector enriches (see [Entity Scope](#entity-scope)) |
| `connector.auto`              | `false`  | Enrich entities automatically when they are created                     |
| `connector.max_tlp`           | `amber`  | Highest TLP of the entities sent to the external source (see [TLP Check](#tlp-check)) |

### What each method is for

| Method / attribute            | Where                         | Purpose                                                          |
| ----------------------------- | ----------------------------- | ---------------------------------------------------------------- |
| `handled_entity_types`        | processor                     | OpenCTI entity types the processor handles (required)            |
| `post_init()`                 | processor                     | Build the API client and shared STIX objects (author, marking)   |
| `can_process(message)`        | processor (optional override) | Filter within a type (e.g. an indicator's `pattern_type`)        |
| `collect(message)`            | processor                     | Fetch raw data about the entity from the external source         |
| `transform(data, message)`    | processor                     | Convert raw data to STIX objects                                 |
| `process(message)`            | `BaseEnrichmentProcessor`     | **Inherited**: runs `collect()` then `transform()`               |
| `callback()` / `start()`      | `InternalEnrichmentConnector` | **Inherited**: listening, scope, TLP, playbook, bundle, errors   |

---

## The Enrichment Message

For each message, the base class validates the data sent by pycti into an `EnrichmentMessage` and
passes it to `can_process()`, `collect()` and `transform()`:

| Attribute                   | Type                    | Content                                                               |
| --------------------------- | ----------------------- | --------------------------------------------------------------------- |
| `message.enrichment_entity` | `OpenCTIEntity`         | The entity as read from OpenCTI: `id`, `entity_type` (e.g. `IPv4-Addr`, `StixFile`), `objectMarking`... |
| `message.stix_entity`       | `StixEntity`            | The entity as a STIX 2.1 object: `id`, `type` (e.g. `ipv4-addr`, `file`), `value`, `hashes`... |
| `message.stix_objects`      | `list[dict]`            | The STIX objects of the bundle containing the entity (in a playbook, the bundle of the previous step) |
| `message.from_playbook`     | `bool`                  | Whether the message comes from a playbook step                        |

`OpenCTIEntity` and `StixEntity` only declare their id and their type. Every other field sent by
pycti can be read as an attribute:

```python
value = message.stix_entity.value                       # STIX property
hashes = getattr(message.stix_entity, "hashes", None)   # optional property
markings = message.enrichment_entity.objectMarking      # OpenCTI field
tlp_levels = message.enrichment_entity.tlp_levels       # e.g. ["TLP:AMBER"]
```

Use `stix_entity` for the values sent to the external source and for the id of the entity in the
bundle. Use `enrichment_entity` for the OpenCTI type and the OpenCTI fields (markings, files...).

The message is frozen, but the dicts nested in it are not: never modify the message in place. To
change the entity, return a new version of it (see
[Updating the enriched entity](#updating-the-enriched-entity)).

For logs, `message.to_log_metadata()` returns the context of the message (`octi_id`,
`octi_entity_type`, `from_playbook`):

```python
self.logger.warning(
    "Skipping a network, the source only accepts a single IP address",
    meta={**message.to_log_metadata(), "value": value},
)
```

---

## Message Handling

The base class handles each message in this order:

```text
invalid message?                        → error
entity type out of connector.scope?     → skip
entity TLP above connector.max_tlp?     → skip
no processor can process the entity?    → skip
several processors can process it?      → error (ValueError)
objects = processor.process(message)    → collect, then transform
no objects returned?                    → nothing to send
otherwise                               → send message.stix_objects + objects
```

The TLP is checked before any processor code runs, including `can_process()`: no data about an
entity above the max TLP can reach the external source.

What happens in each case:

| Case                                    | Manual / automatic enrichment                              | Playbook step                         |
| --------------------------------------- | ---------------------------------------------------------- | ------------------------------------- |
| Objects returned                        | Bundle sent, work completed ("Entity enriched with N objects") | Enriched bundle sent                  |
| `transform()` returns `[]`              | Nothing sent, work completed ("No enrichment data found")  | Original bundle sent back             |
| Skip (scope, TLP, no processor)         | Nothing sent, work completed with the reason               | Original bundle sent back             |
| Error (exception in a processor, invalid message, several processors) | Exception logged with its traceback, work in error | Exception logged, original bundle sent back |

A skip is not a failure: it is a configured policy, so the work completes with the reason (for
example `Entity TLP is not allowed (max TLP: amber)`) instead of ending in error. The outcome
messages are generic and owned by the base class.

---

## Entity Scope

`connector.scope` (`CONNECTOR_SCOPE`) lists the entity types the connector enriches. The base class
compares it with the **OpenCTI type** of the entity (`enrichment_entity.entity_type`),
case-insensitively:

```yaml
connector:
  scope: 'IPv4-Addr,IPv6-Addr,Domain-Name,StixFile'
```

Use OpenCTI type names, not STIX types: a file is `StixFile` (its STIX type is `file`), an
autonomous system is `Autonomous-System`.

**Common scopes:**
- **Observables**: `IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, `Url`, `StixFile`, `Email-Addr`
- **Indicators**: `Indicator`
- **Vulnerabilities**: `Vulnerability`
- **Malware**: `Malware`
- **Threat Actors**: `Threat-Actor-Group`, `Threat-Actor-Individual`

Outside playbooks, the platform only sends entities in the scope, except for a request through the
API. In a playbook, any entity can reach the connector: an entity out of scope is normal there and
logged at INFO (WARNING outside playbooks).

### Several entity types

A connector can enrich several entity types:

- with one processor that declares them all
  (`handled_entity_types = frozenset({"IPv4-Addr", "IPv6-Addr"})`), when the source call and the
  conversion are the same;
- with one processor per entity type, when they differ (e.g. an `IPv4Processor` and a
  `DomainNameProcessor`).

For a given entity, **exactly one** processor must accept it: the base class raises `ValueError`
when several do. The order of the processors does not matter.

### Filtering within a type: `can_process()`

By default, `can_process()` checks that the entity type is in `handled_entity_types`. Override it
to filter further, and call `super()` to keep the type check:

```python
class StixPatternProcessor(BaseEnrichmentProcessor[ConnectorSettings]):
    handled_entity_types = frozenset({"Indicator"})

    def can_process(self, message: EnrichmentMessage) -> bool:
        return (
            super().can_process(message)
            and getattr(message.stix_entity, "pattern_type", None) == "stix"
        )
```

An entity that no processor accepts is skipped and logged at WARNING. `can_process()` runs after
the TLP check, but it must not call the external source anyway: put network calls in `collect()`.

---

## TLP Check

`connector.max_tlp` (`CONNECTOR_MAX_TLP`) is the highest TLP of the entities the connector may send
to the external source. It is a `TLPLevel` defined by `BaseInternalEnrichmentConnectorConfig`,
defaults to `amber`, and accepts any case, with or without the `TLP:` prefix (`TLP:AMBER+STRICT`
and `amber+strict` are the same).

The base class checks it with pycti's `check_max_tlp()`, which holds the TLP order of the platform:

```
TLP:CLEAR (lowest) → TLP:WHITE → TLP:GREEN → TLP:AMBER → TLP:AMBER+STRICT → TLP:RED (highest)
```

- Every TLP marking of the entity is checked: an entity is skipped as soon as one of them is above
  the max TLP.
- An entity without TLP marking is enriched.
- An entity with a custom TLP marking (e.g. `TLP:EX:CHEMICAL`) is skipped: it cannot be compared.
- The TLP is read from the markings stored in OpenCTI (`enrichment_entity`). In a playbook, a
  marking added by an earlier step and not saved yet is not seen.

**Configuration examples:**
- `CONNECTOR_MAX_TLP=TLP:GREEN` - Process CLEAR, WHITE, and GREEN entities
- `CONNECTOR_MAX_TLP=TLP:AMBER` - Process up to and including AMBER
- `CONNECTOR_MAX_TLP=TLP:RED` - Process all TLP levels

Do not add a max TLP setting to the connector's own section. To change its default, override the
field in the connector config:

```python
from connectors_sdk.models.enums import TLPLevel


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    max_tlp: TLPLevel = Field(
        default=TLPLevel.AMBER_STRICT,
        description="The highest TLP of the entities the connector is allowed to enrich.",
    )
```

`connector.max_tlp` is an input ceiling. The marking the connector applies to the objects it
creates is a different setting, in the connector's own section (`tlp_level` in the examples above).

---

## Playbook Compatibility

In a playbook, the connector must send **exactly one bundle** per message: sending none stalls the
playbook, sending two runs the next step twice. The base class guarantees it on every path (success,
no data, skip, error), and creates the helper with `playbook_compatible=True`.

So a connector built on the base class is playbook-compatible by construction. Declare it in
`__metadata__/connector_manifest.json`:

```json
{
  "title": "My Enrichment Connector",
  "slug": "my-enrichment",
  "playbook_supported": true,
  "container_type": "INTERNAL_ENRICHMENT",
  ...
}
```

Two limits remain:

- If sending the enriched bundle fails (platform unreachable, timeout), the original bundle is not
  sent either, since the platform may already have run the next step: the playbook stops at this
  step, with the error logged.
- An entity sent back with another id (e.g. a file rebuilt with an MD5, see below) is a second
  object in the bundle: the next playbook steps keep working on the original entity until
  ingestion merges the two.

---

## Building the Enrichment Result

### What `transform()` returns

`transform()` returns the objects to add to the bundle, as `connectors-sdk` models (preferred),
`stix2` objects or STIX dicts:

1. **The author and the marking objects** used by the new objects, otherwise references to them
   break (`MISSING_REFERENCE_ERROR`).
2. **The new objects** (observables, locations, notes...).
3. **The relationships** between the entity and the new objects.
4. **The enriched entity itself**, when the enrichment changes it (score, labels, external
   references...).

Return `[]` when there is nothing to add. Never return `message.stix_objects`: the base class adds
them.

The base class then sends `message.stix_objects` followed by the objects returned. The original
objects keep the references to the entity valid. An object returned with the id of an original
object replaces it in the bundle. The bundle is sent with `cleanup_inconsistent_bundle=True`.

Always use deterministic ids: `connectors-sdk` models compute them. Never pass a `datetime` to a
`Note` id: a note without creation date gives the same note on every enrichment.

### Linking to the entity

To use the entity as the source or target of a relationship, either rebuild it as an SDK model with
the same values (see below), or use a `Reference` to its id:

```python
from connectors_sdk.models import Reference

entity = Reference(id=message.stix_entity.id)
relationship = Relationship(
    type=RelationshipType.RELATED_TO,
    source=entity,
    target=domain,
    author=self.author,
    markings=[self.tlp_marking],
)
return [self.author, self.tlp_marking, domain, relationship]
```

A `Reference` returned in the list is ignored: it only points to an object already in the bundle.

### Updating the enriched entity

To add data to the entity itself, return a new version of it, built with the same values so that
it has the **same id** (Spur's `_build_ip()`):

```python
from connectors_sdk.models import ExternalReference, IPV4Address

value = message.stix_entity.value
ip = IPV4Address(
    value=value,
    labels=["my-source:vpn"],
    score=75,
    external_references=[
        ExternalReference(source_name="My Source", url=f"https://example.com/ip/{value}")
    ],
)
```

Set only the fields the enrichment provides. **The connector does not merge anything: OpenCTI
does.**

- In manual or automatic mode, the worker upsert ignores the fields absent from the bundle and adds
  multiple references (markings, labels, external references) to the existing ones. Single values
  such as the score replace the existing value.
- In a playbook, the playbook executor deep-merges each returned object with the previous step's
  object of the same id.

Do not set `author` or `markings` on the rebuilt entity unless the enrichment means to change them:
the connector's markings would be added to the entity, and its author could be replaced.

Hashed observables are the exception to "same id": the id of a file uses the first hash in a fixed
order (MD5, SHA-1, SHA-256...), so adding an MD5 to a file known by its SHA-256 gives another id.
Send it as is: OpenCTI deduplicates files by their hashes and keeps the new id in
`x_opencti_stix_ids`.

---

## Errors and Logging

Processors use the SDK exceptions (see
[HOW-TO-Handle-errors-in-connectors](../connectors-sdk/docs/HOW-TO-Handle-errors-in-connectors.md)),
and always `raise ... from err`:

| Situation                                          | What to do                                                           |
| -------------------------------------------------- | -------------------------------------------------------------------- |
| The source does not know the entity (e.g. HTTP 404) | `collect()` returns an empty value (`None`, `{}`) and `transform()` returns `[]`: not an error |
| The source call fails                              | `collect()` raises `DataRetrievalError`                              |
| One item fails to convert                          | `transform()` skips it and logs a WARNING                            |
| Nothing can be converted                           | `transform()` raises `UseCaseError`                                  |
| The entity cannot be sent to the source (e.g. a CIDR network for an IP-only API) | Log a WARNING and return no data                     |

An exception raised by a processor puts the work in error (manual/automatic mode) or sends the
original bundle back (playbook), after the base class logs it with its traceback. Do not catch
exceptions only to log them.

Each processor has a `self.logger`. Log a static message with a `meta=` dict, never an f-string:

```python
self.logger.info("Spur has no metadata for this tag", meta={"tag": tag})
```

The base class already logs the skips, the outcome and the errors of each message.

---

## Testing

A processor can be tested without OpenCTI: inject the settings, call `post_init()`, mock the API
client, and build an `EnrichmentMessage` from a dict. The template's `tests/conftest.py` provides
a `connector_settings` fixture and an `ipv4_message` fixture built this way, and
`tests/tests_connector/enrichment_processors/` tests its example processor:

```python
from unittest.mock import MagicMock

from connector.enrichment_processors import IPv4Processor
from connectors_sdk import ApiNotFoundError, EnrichmentMessage
from connectors_sdk.models import IPV4Address
from my_client import MyClient


def make_message(value: str = "1.2.3.4") -> EnrichmentMessage:
    stix_entity = {"type": "ipv4-addr", "id": IPV4Address(value=value).id, "value": value}
    return EnrichmentMessage.model_validate(
        {
            "enrichment_entity": {
                "id": "opencti-id",
                "entity_type": "IPv4-Addr",
                "objectMarking": [],
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
            "from_playbook": False,
        }
    )


def test_processor_should_return_nothing_when_the_source_does_not_know_the_ip(
    connector_settings,
):
    # Given a processor whose client does not know the IP
    processor = IPv4Processor()
    processor.inject_dependencies(settings=connector_settings)
    processor.post_init()
    processor.client = MagicMock(spec=MyClient)
    processor.client.get_ip.side_effect = ApiNotFoundError("Not found")

    # When the IP is enriched
    objects = processor.process(make_message())

    # Then nothing is returned
    assert objects == []
```

To test the whole flow, patch the helper created by the base class and call `callback()` with the
raw message data, as in
[spur-enrichment's `test_connector.py`](../internal-enrichment/spur-enrichment/tests/tests_connector/test_connector.py).
The helper is created in `start()`, so `InternalEnrichmentConnector(...)` itself never connects to
OpenCTI.

`run_test.sh` blocks network access: mock every call to the external source.

---

## Best Practices

### `auto: false` for Quota-Based Sources

`connector.auto` defaults to `false`. **Keep it that way for paid or quota-limited sources.**
Automatic enrichment on every new observable will rapidly exhaust API quotas, especially on large
platforms with hundreds of thousands of observables. Enrichment should then be triggered manually
by analysts, or by playbooks with controlled targeting.

### Rate Limiting and "Not Found"

Handle the source limits in the API client, not in the processor: retry HTTP `429` with a backoff,
and turn an HTTP `404` (entity unknown to the source) into an empty result rather than an error.
The `connectors-sdk` client does the first part: `BaseClientApi` retries transient errors (`408`,
`429`, `5xx`) with an exponential backoff and accepts a proactive `RateLimit`, and its exceptions
(`ApiNotFoundError`, `ApiRateLimitError`...) tell the cases apart.

### Send Results Only Through the Bundle

Never write to OpenCTI through `helper.api` or direct mutations: they bypass confidence level checks
and deduplication. Processors do not receive the helper: everything they produce goes into the
bundle sent by the base class.

### One Message, One Bundle

A processor that needs several endpoints calls them all in `collect()`. Do not create works, send
several bundles per message, or keep data between messages: a connector that needs this cannot use
the base class as is.

---

## Complete Example

[internal-enrichment/spur-enrichment](../internal-enrichment/spur-enrichment) enriches IPv4 and IPv6
addresses with the Spur Context API:

| File                                                                                                   | Content                                                              |
| ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| [`src/main.py`](../internal-enrichment/spur-enrichment/src/main.py)                                     | Entry point: settings, one processor, `InternalEnrichmentConnector`  |
| [`src/connector/settings.py`](../internal-enrichment/spur-enrichment/src/connector/settings.py)         | `BaseInternalEnrichmentConnectorSettings` with a `spur` section      |
| [`src/connector/processor.py`](../internal-enrichment/spur-enrichment/src/connector/processor.py)       | `SpurIPProcessor`: `collect()` (IP context, tag metadata), `transform()` (enriched IP, autonomous system, locations, infrastructures, notes) |
| [`src/spur_client/`](../internal-enrichment/spur-enrichment/src/spur_client)                            | API client and Pydantic models of the responses                      |
| [`tests/tests_connector/`](../internal-enrichment/spur-enrichment/tests/tests_connector)                | Processor unit tests, and a test of the whole flow through `callback()` |

Things it shows:

- one processor for two entity types (`IPv4-Addr`, `IPv6-Addr`);
- a value the source cannot query (a CIDR network) skipped with a WARNING and no data;
- source failures raised as `DataRetrievalError`, an optional second call skipped with a WARNING
  when it fails;
- the enriched IP rebuilt with the same value, without author or markings, so that OpenCTI merges
  its labels, score and external reference;
- notes without creation date, so that the same content gives the same note.

---

## Legacy Connectors

Most existing internal enrichment connectors predate `InternalEnrichmentConnector`: they create
their own `OpenCTIConnectorHelper`, call `helper.listen()`, and check the scope, the TLP and the
playbook mode themselves. **Do not copy this pattern into new code.** To move such a connector to
the base class, follow
[HOW_TO_Migrate_an_enrichment_connector](../connectors-sdk/docs/HOW_TO_Migrate_an_enrichment_connector.md).

When fixing a legacy connector without migrating it, keep these rules:

- **Scope**: compare the OpenCTI type of the entity (`data["enrichment_entity"]["entity_type"]`)
  with the scope, for example with
  `InternalEnrichmentConnector.is_entity_in_scope(entity_type, settings.connector.scope)`.
  Comparing the `entity_id` prefix with `helper.connect_scope` fails for types whose STIX prefix
  differs from the OpenCTI type (`StixFile` → `file--`).
- **TLP**: before any external call, check every TLP of the entity with
  `InternalEnrichmentConnector.is_entity_tlp_allowed(tlp_levels, settings.connector.max_tlp)`. It
  converts both sides to the `TLP:XXX` form that pycti's `check_max_tlp()` expects (which raises
  `KeyError` on `amber+strict`).
- **Playbooks**: when the message comes from a playbook (`data.get("event_type")` is falsy), every
  code path (out of scope, TLP refused, no data, error) must send exactly one bundle, containing
  the original `data["stix_objects"]`. Only then set `playbook_compatible=True` on the helper and
  `"playbook_supported": true` in the manifest.
- **Bundles**: send results only through `stix2_create_bundle()` and `send_stix2_bundle()`.
- **Entity updates**: put the enriched entity in the bundle in place of the original one (same id),
  instead of modifying `data["stix_entity"]` in place. Outside playbooks, `stix_entity` is usually
  not the object inside `stix_objects`, so an in-place change is lost. Never send both versions:
  OpenCTI merges the enriched entity with the stored one, but it does not deduplicate two objects
  with the same id within a bundle, so in a playbook both go to the next steps.

A legacy connector's `process_message()` typically looks like this:

```python
def process_message(self, data: dict) -> str:
    opencti_entity = data["enrichment_entity"]
    stix_objects = data["stix_objects"]
    is_playbook = not data.get("event_type")

    if not InternalEnrichmentConnector.is_entity_in_scope(
        opencti_entity["entity_type"], self.config.connector.scope
    ):
        if is_playbook:
            self._send_bundle(stix_objects)  # Original bundle back
        return "Entity out of scope"

    tlp_levels = [
        marking["definition"]
        for marking in opencti_entity.get("objectMarking", [])
        if marking.get("definition_type") == "TLP"
    ]
    if not InternalEnrichmentConnector.is_entity_tlp_allowed(
        tlp_levels, self.config.connector.max_tlp
    ):
        if is_playbook:
            self._send_bundle(stix_objects)
        return "Entity TLP not allowed"

    try:
        new_objects = self._collect_intelligence(data["stix_entity"])
    except Exception:
        if is_playbook:
            self._send_bundle(stix_objects)
        raise

    if not new_objects:
        if is_playbook:
            self._send_bundle(stix_objects)
        return "No enrichment data found"

    # Keyed by id: the enriched entity replaces the original one instead of
    # being sent next to it
    bundle_objects = {obj["id"]: obj for obj in stix_objects}
    bundle_objects.update({obj["id"]: obj for obj in new_objects})
    self._send_bundle(list(bundle_objects.values()))
    return f"Entity enriched with {len(new_objects)} objects"
```

Every branch above is code that `InternalEnrichmentConnector` already provides.

---

## Next Steps

- Write a processor step by step: [HOW_TO_Write_an_enrichment_processor](../connectors-sdk/docs/HOW_TO_Write_an_enrichment_processor.md)
- Review [Stream Connector Specifications](./04-stream-specifications.md)
- Review [Code Quality & Standards](./05-code-quality-standards.md)
