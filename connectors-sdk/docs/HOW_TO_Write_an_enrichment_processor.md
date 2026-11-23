# How to write an internal enrichment connector with `InternalEnrichmentConnector`

This guide builds an internal enrichment connector on `InternalEnrichmentConnector`, step by step.
The connector only fetches data about an entity and converts it to STIX: the base class checks the
scope and the TLP, handles playbooks and sends the bundle.

Reference material:

- [Internal Enrichment Connector Specifications](../../docs/03-internal-enrichment-specifications.md):
  what the base class does for each message, and the rules a processor follows.
- [internal-enrichment/spur-enrichment](../../internal-enrichment/spur-enrichment): a complete
  connector built this way.
- [TDR: Base internal enrichment connector](../TDRs/2026-10-05-Internal_enrichment_connector_base.md):
  the design decisions.

The examples enrich IPv4 addresses with a fictional "My Source" API.

## 1. Create the connector

```bash
cd templates && sh create_connector_dir.sh -t internal-enrichment -n my-source
```

The [template](../../templates/internal-enrichment) is already built on `InternalEnrichmentConnector`:
an example processor (`src/connector/enrichment_processors/ipv4_processor.py`), an API client on
`BaseClientApi` (`src/template_client/`) and their tests. Its `TODO` checklists and the
"How to adapt this template" section of its README list what to change.

Replace every `Template`/`template` reference, generate a UUIDv4 for the connector `id` default and
fill in `__metadata__/connector_manifest.json`. Keep `"playbook_supported": true`: a connector built
on the base class supports playbooks on every code path.

`src/requirements.txt` holds `connectors-sdk` and `pycti`: keep `pycti` at the exact version
`connectors-sdk` pins, otherwise dependency resolution fails.

## 2. Define the settings

`src/connector/settings.py` extends `BaseInternalEnrichmentConnectorSettings`. The `connector`
section declares the defaults of the connector, the source section its own settings:

```python
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseInternalEnrichmentConnectorConfig,
    BaseInternalEnrichmentConnectorSettings,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    id: str = Field(
        description="The UUID of the connector.",
        default="00000000-0000-4000-8000-000000000000",  # Generate your own UUIDv4
    )
    name: str = Field(description="The name of the connector.", default="My Source")
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["IPv4-Addr"],
    )


class MySourceConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        description="My Source API base URL.",
        default="https://api.example.com",
    )
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

- `scope` uses OpenCTI entity types (`IPv4-Addr`, `StixFile`, `Indicator`...), not STIX types.
- `connector.max_tlp` (`CONNECTOR_MAX_TLP`, default `amber`) and `connector.auto` (default
  `false`) come from `BaseInternalEnrichmentConnectorConfig`: do not redeclare them in
  `MySourceConfig`. To change the default max TLP, override `max_tlp` in
  `InternalEnrichmentConnectorConfig`.
- `tlp_level` is the marking of the objects the connector creates, not the max TLP of the entities
  it receives.

## 3. Write the processor

A processor subclasses `BaseEnrichmentProcessor`, parameterized with the settings class. Put each
processor in its own module under `src/connector/enrichment_processors/` and export it from the
package's `__init__.py`:

```python
from typing import Any

from connector.settings import ConnectorSettings
from connectors_sdk import BaseEnrichmentProcessor, EnrichmentMessage
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from my_source_client import MySourceClient


class IPv4Processor(BaseEnrichmentProcessor[ConnectorSettings]):
    """Enrich an IPv4 address with the My Source API."""

    handled_entity_types = frozenset({"IPv4-Addr"})

    def post_init(self) -> None:
        """Build the API client, the author and the marking once."""
        my_source = self.settings.my_source
        self.client = MySourceClient(
            base_url=str(my_source.api_base_url),
            api_key=my_source.api_key.get_secret_value(),
        )
        self.author = OrganizationAuthor(name="My Source")
        self.tlp_marking = TLPMarking(level=my_source.tlp_level)
```

- `handled_entity_types` is required. Every type of `connector.scope` must be handled by a
  processor, otherwise the connector refuses to start.
- `post_init()` runs once, after the base class injects `self.settings`. Build everything that does
  not depend on a message here.
- The processor handles every message: keep message data in local variables, never on `self`.

### `collect(message)`: fetch, no STIX

```python
from connectors_sdk import ApiClientError, ApiNotFoundError
from connectors_sdk.exceptions.error import DataRetrievalError

    def collect(self, message: EnrichmentMessage) -> dict | None:
        """Fetch the IP report, `None` when My Source does not know the IP."""
        try:
            return self.client.get_ip_report(message.stix_entity.value)
        except ApiNotFoundError:
            self.logger.info(
                "IP address not found in My Source", meta=message.to_log_metadata()
            )
            return None
        except ApiClientError as err:
            raise DataRetrievalError("Failed to fetch the My Source IP report") from err
```

- Read the values to send to the source from `message.stix_entity` (`value`, `hashes`...). Use
  `message.enrichment_entity` for OpenCTI fields (`entity_type`, `objectMarking`...).
- An entity unknown to the source is not an error: return an empty value. With a client built on
  `BaseClientApi`, an HTTP 404 raises `ApiNotFoundError`.
- A failure raises `DataRetrievalError`. The base class logs it, puts the work in error, and in a
  playbook sends the original bundle back.

### `transform(data, message)`: convert, no network

```python
from connectors_sdk.models import AutonomousSystem, IPV4Address, Relationship
from connectors_sdk.models.enums import RelationshipType

    def transform(self, data: dict | None, message: EnrichmentMessage) -> list[Any]:
        """Convert the IP report into the enriched IP and its autonomous system."""
        if not data:
            return []
        ip = IPV4Address(value=message.stix_entity.value, score=data["score"])
        objects: list[Any] = [self.author, self.tlp_marking, ip]
        if data.get("asn"):
            autonomous_system = AutonomousSystem(
                number=data["asn"], author=self.author, markings=[self.tlp_marking]
            )
            objects.append(autonomous_system)
            objects.append(
                Relationship(
                    type=RelationshipType.BELONGS_TO,
                    source=ip,
                    target=autonomous_system,
                    author=self.author,
                    markings=[self.tlp_marking],
                )
            )
        return objects
```

- Return the author and the marking with the new objects, and `[]` when there is nothing to add.
- Never return `message.stix_objects`: the base class sends them with your objects.
- A single item that fails to convert is skipped and logged at WARNING; raise `UseCaseError` only
  when nothing can be converted.

### Enriching the entity itself

The `ip` above is the entity received, rebuilt with the same value: it has the same id, replaces
the entity in the bundle, and OpenCTI merges it with the stored entity (the worker upsert adds the
labels and external references, and replaces the score). The connector never merges properties
itself.

- Set only the fields the enrichment provides.
- Do not set `author` or `markings` on it, unless the enrichment means to change them.
- To link to the entity without rebuilding it, use `Reference(id=message.stix_entity.id)` as the
  source or target of a relationship.
- A file rebuilt with a new hash may get another id (the id uses MD5 first): send it as is, OpenCTI
  deduplicates files by their hashes.

### Several entity types

- Same API call and conversion for several types: one processor,
  `handled_entity_types = frozenset({"IPv4-Addr", "IPv6-Addr"})`.
- Different calls or conversions: one processor per type.
- Several processors for the same type (e.g. one per indicator `pattern_type`): override
  `can_process()` and call `super().can_process(message)`. Exactly one processor must accept each
  entity.

## 4. Wire it in `main.py`

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

`start()` creates the `OpenCTIConnectorHelper` (with `playbook_compatible=True`), calls
`inject_dependencies()` and `post_init()` on each processor, then listens to messages.

## 5. Test it

Test the processor without OpenCTI. The template's `tests/conftest.py` provides a
`connector_settings` fixture and an `ipv4_message` fixture, an `EnrichmentMessage` built from a dict
as the connector builds it. Add one message fixture per entity type your processors enrich.

```python
from unittest.mock import MagicMock

import pytest
from connector.enrichment_processors import IPv4Processor
from connectors_sdk.models import IPV4Address


@pytest.fixture
def processor(connector_settings) -> IPv4Processor:
    processor = IPv4Processor()
    processor.inject_dependencies(settings=connector_settings)
    processor.post_init()
    processor.client = MagicMock()
    return processor


def test_processor_should_return_the_enriched_ip(processor, ipv4_message):
    # Given a client that returns a report
    processor.client.get_ip_report.return_value = {"score": 80, "asn": 64496}

    # When the IP is enriched
    objects = processor.process(ipv4_message)

    # Then the enriched IP has the id of the IP received
    ip = next(obj for obj in objects if isinstance(obj, IPV4Address))
    assert ip.id == ipv4_message.stix_entity.id
    assert ip.score == 80
```

Also cover: no data (`[]`), a source failure (`DataRetrievalError`), and each entity type. Do not
test the scope, the TLP, the playbooks or the bundle: the SDK tests them. The template's
`tests/tests_connector/test_connector.py` checks that the processors handle every scope type; for a
test of the whole flow through `InternalEnrichmentConnector.callback()`, see spur-enrichment's
[`test_connector.py`](../../internal-enrichment/spur-enrichment/tests/tests_connector/test_connector.py).

Run the tests with `run_test.sh` (see the repository `AGENTS.md`). It blocks network access: mock
every call to the source.

## 6. Checklist

- [ ] Processors never check the scope or the TLP, never send bundles, never use the helper.
- [ ] `collect()` makes the network calls, `transform()` makes none.
- [ ] `transform()` returns the author and the marking, and `[]` when there is nothing to add.
- [ ] The enriched entity keeps its id and carries only the new fields.
- [ ] Every id is deterministic (SDK models; no `datetime` in a `Note` id).
- [ ] No max TLP setting in the connector's own section.
- [ ] `connector.auto` stays `false` for a paid or quota-limited source.
- [ ] `"playbook_supported": true` in the manifest.
- [ ] Config schema regenerated (`mise run gs internal-enrichment/my-source`), formatting, flake8,
      STIX ID pylint and connector-linter pass.
