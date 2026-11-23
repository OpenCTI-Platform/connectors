# How to migrate an internal enrichment connector to `InternalEnrichmentConnector`

This guide moves an existing internal enrichment connector (its own class, its own
`OpenCTIConnectorHelper`, a `helper.listen()` callback that checks the scope, the TLP and the
playbook mode by hand) to the `InternalEnrichmentConnector` base class of `connectors-sdk`.

Most of the migration is deleting code: the base class owns the helper, the listening, the scope
and TLP checks, the playbook handling and the bundle sending. What remains is the source-specific
code, split into `collect()` and `transform()`.

Reference material:

- [Internal Enrichment Connector Specifications](../../docs/03-internal-enrichment-specifications.md)
- [HOW_TO_Write_an_enrichment_processor](HOW_TO_Write_an_enrichment_processor.md)
- [internal-enrichment/spur-enrichment](../../internal-enrichment/spur-enrichment), a connector
  built on the base class
- [TDR: Base internal enrichment connector](../TDRs/2026-10-05-Internal_enrichment_connector_base.md)

## Prerequisites

- The connector uses Pydantic settings (`BaseConnectorSettings`). If it still reads its
  configuration with `get_config_variable` or a `config.yml` loader, migrate it to
  manager-supported mode first (`.claude/skills/connector-manager-supported-migration/references/procedure.md`).
- The connector does not need what the base class does not offer (see
  [When the base class does not fit](#when-the-base-class-does-not-fit)).

## What moves where

| Legacy code                                                              | With `InternalEnrichmentConnector`                                     |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| `OpenCTIConnectorHelper(config=..., playbook_compatible=...)`            | Deleted: created by `start()`, always playbook-compatible             |
| `run()` / `helper.listen(message_callback=self.process_message)`          | Deleted: `InternalEnrichmentConnector(...).start()` in `main.py`       |
| Scope check (`entity_in_scope()`, `helper.connect_scope`, `entity_id` prefix) | Deleted: `connector.scope` and the processors' `handled_entity_types` |
| TLP extraction and `helper.check_max_tlp(...)`                           | Deleted: `connector.max_tlp`, checked before any processor runs       |
| Playbook branches (`data.get("event_type")`, sending `stix_objects` back) | Deleted                                                                |
| `_send_bundle()`, `stix2_create_bundle()`, `send_stix2_bundle()`         | Deleted: `transform()` returns the objects                             |
| Status strings returned by the callback                                  | Deleted: the outcome messages are generic                              |
| `try` / `except` that logs and returns an error string                    | Deleted: raise `DataRetrievalError` / `UseCaseError`, the base logs it |
| API client, author and marking built in `__init__()`                     | `post_init()` of the processor                                         |
| API calls (`_collect_intelligence()`, `process_message()`...)            | `collect(message)`                                                     |
| STIX conversion (`converter_to_stix`)                                     | `transform(data, message)` (a converter class can stay, called from `transform()`) |
| Dispatch on the entity type (`if entity_type == "ipv4-addr": ...`)       | One processor per type, or one processor with several `handled_entity_types` |
| `data["stix_entity"]["value"]`                                           | `message.stix_entity.value`                                            |
| `data["enrichment_entity"]["objectMarking"]`                             | `message.enrichment_entity.objectMarking`                              |
| `self.helper.connector_logger.info(...)`                                 | `self.logger.info("Static message", meta={...})`                       |
| Changes to `data["stix_entity"]` in place, `put_attribute_in_extension()` | Return the entity rebuilt with the same id (see step 3)               |

## Step 1: settings

Make the settings extend the internal enrichment classes:

```python
from connectors_sdk import (
    BaseInternalEnrichmentConnectorConfig,
    BaseInternalEnrichmentConnectorSettings,
)


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    ...  # id, name, scope defaults: unchanged


class ConnectorSettings(BaseInternalEnrichmentConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    my_source: MySourceConfig = Field(default_factory=MySourceConfig)
```

Check three things:

- **Scope values are OpenCTI types.** The base class compares `connector.scope` with
  `enrichment_entity.entity_type`, case-insensitively. `ipv4-addr` works, but `file` does not
  match `StixFile`: use `StixFile`. Every scope type must be declared by a processor, otherwise the
  connector refuses to start.
- **The max TLP is `connector.max_tlp`.** A connector-specific max TLP setting stays declared as a
  `DeprecatedField` that points to it, so existing deployments keep working:

  ```python
  class MySourceConfig(BaseConfigModel):
      max_tlp: str | None = DeprecatedField(
          deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
          new_namespace="connector",
          new_namespaced_var="max_tlp",
          description="Do not enrich entities marked above this TLP level.",
      )
  ```

  If the old setting defaulted to another level than `amber`, keep its default by overriding
  `max_tlp` in `InternalEnrichmentConnectorConfig`.
- **The marking of the objects created** (often `tlp_level`) stays in the connector's own section:
  it is not the max TLP.

## Step 2: processors

Move the source-specific code into one or more `BaseEnrichmentProcessor[ConnectorSettings]`, one
module per processor under `src/connector/enrichment_processors/`, as in the
[template](../../templates/internal-enrichment).

Before:

```python
class MyConnector:
    def __init__(self, config, helper):
        self.config = config
        self.helper = helper
        self.client = MyClient(api_key=config.my_source.api_key.get_secret_value())
        self.converter_to_stix = ConverterToStix(helper, config.my_source.tlp_level)

    def process_message(self, data: dict) -> str:
        stix_objects = data["stix_objects"]
        if not self.entity_in_scope(data):
            if not data.get("event_type"):
                self._send_bundle(stix_objects)
                return "Entity out of scope"
            raise ValueError("Entity type not supported")
        self.extract_and_check_markings(data["enrichment_entity"])
        try:
            report = self.client.get_ip(data["stix_entity"]["value"])
        except Exception as err:
            self.helper.connector_logger.error("Enrichment failed", {"error": str(err)})
            self._send_bundle(stix_objects)
            return f"Error: {err}"
        if not report:
            self._send_bundle(stix_objects)
            return "No data"
        new_objects = self.converter_to_stix.convert(report, data["stix_entity"])
        return self._send_bundle(stix_objects + new_objects)

    def run(self):
        self.helper.listen(message_callback=self.process_message)
```

After:

```python
class IPv4Processor(BaseEnrichmentProcessor[ConnectorSettings]):
    handled_entity_types = frozenset({"IPv4-Addr"})

    def post_init(self) -> None:
        self.client = MyClient(api_key=self.settings.my_source.api_key.get_secret_value())
        self.converter_to_stix = ConverterToStix(self.settings.my_source.tlp_level)

    def collect(self, message: EnrichmentMessage) -> dict | None:
        try:
            return self.client.get_ip(message.stix_entity.value)
        except MyClientError as err:
            raise DataRetrievalError("Failed to fetch the IP report") from err

    def transform(self, data: dict | None, message: EnrichmentMessage) -> list[Any]:
        if not data:
            return []
        return self.converter_to_stix.convert(data, message.stix_entity.value)
```

- The converter no longer receives the helper: build its objects with SDK models, and log with its
  own `logging` logger or from the processor.
- `transform()` returns the author and the marking with the new objects, and never
  `message.stix_objects`.
- A processor is created once and handles every message: move per-message attributes
  (`self.stix_objects_list`, `self.tlp`...) to local variables.
- A connector that enriched several entity types in one class gets one processor per type, or one
  processor with several `handled_entity_types` when the code is the same. A filter within a type
  (e.g. on an indicator's `pattern_type`) goes in `can_process()`.

## Step 3: entity updates

Legacy connectors often modify the received entity: `data["stix_entity"]` changed in place,
`OpenCTIStix2.put_attribute_in_extension()`, `x_opencti_*` keys added to a copy. Replace this with a
new version of the entity, built with an SDK model from the same values, so that it has the same id:

```python
ip = IPV4Address(
    value=message.stix_entity.value,
    score=data["score"],
    labels=data["tags"] or None,
)
```

It replaces the entity in the bundle, and OpenCTI merges it with the stored entity (worker upsert,
or playbook executor). Set only the new fields, without `author` or `markings`. Do not merge
properties in the connector. The SDK models write the OpenCTI properties where pycti reads them,
in both manual and playbook mode.

## Step 4: `main.py`

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

Delete the connector class, its `run()` and the helper creation.

## Step 5: manifest, samples and README

- `__metadata__/connector_manifest.json`: `"playbook_supported": true`.
- `config.yml.sample` and `docker-compose.yml`: `CONNECTOR_MAX_TLP` instead of the old max TLP
  variable, and scope values as OpenCTI types.
- README: the behaviour changes below.
- Regenerate the config schema: `mise run gs internal-enrichment/my-connector`.

## Step 6: tests

- Delete the tests of the scope, TLP, playbook and bundle-sending branches: the SDK tests them.
- Test each processor directly: `inject_dependencies(settings=...)`, `post_init()`, a mocked client,
  and an `EnrichmentMessage.model_validate({...})`. The template's `tests/conftest.py` and
  `tests/tests_connector/` show the fixtures and tests to copy (see also
  [HOW_TO_Write_an_enrichment_processor](HOW_TO_Write_an_enrichment_processor.md#5-test-it)).
- Keep one test of the whole flow through `InternalEnrichmentConnector.callback()` with a patched
  helper, as in spur-enrichment's
  [`test_connector.py`](../../internal-enrichment/spur-enrichment/tests/tests_connector/test_connector.py).

Then run formatting, flake8, the STIX ID pylint, connector-linter (its enrichment checks VC304,
VC318 to VC322 recognize connectors built on the base class) and `run_test.sh`.

## Behaviour changes

Tell users about these in the README and the pull request:

- An entity out of scope, above the max TLP, or that no processor supports, is **skipped**: the work
  completes with the reason instead of ending in error (or completing with an ERROR log).
- A source failure puts the work in error, with the exception logged. Some legacy connectors
  reported it as a successful work.
- The outcome messages are generic ("Entity enriched with N objects", "No enrichment data found",
  the skip reason): detailed success messages (verdict, score) are gone.
- Every TLP marking of the entity is checked, not only the first or the last; a custom TLP marking
  is refused.
- In a playbook, every path sends exactly one bundle: no more stalled playbooks on a skip, no data
  or an error.

## When the base class does not fit

Keep the legacy class when the connector:

- needs the OpenCTI API (`helper.api`), e.g. to read files or pre-create labels with a color:
  processors do not receive the helper;
- sends several bundles per message, or creates its own works;
- needs detailed outcome messages on the work.

It can still drop its hand-written scope and TLP checks for the static helpers
`InternalEnrichmentConnector.is_entity_in_scope()` and
`InternalEnrichmentConnector.is_entity_tlp_allowed()` (see the
[Legacy Connectors](../../docs/03-internal-enrichment-specifications.md#legacy-connectors) section
of the specifications).
