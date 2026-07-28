# AGENTS.md — Internal Enrichment Connectors

Scope: everything under `internal-enrichment/`. Read the repo-root [`AGENTS.md`](../AGENTS.md)
first (universal rules: STIX IDs, config, logging, formatting/linting/tests). Full spec:
[`docs/03-internal-enrichment-specifications.md`](../docs/03-internal-enrichment-specifications.md).

## What this connector type does

Enriches entities that **already exist** in OpenCTI with extra context/relationships
from an external source. Event-driven (triggered on entity create/update), push-based
(OpenCTI sends the entity to the connector), stateless (each request independent),
scope-based (only processes configured entity types).

## Class shape

```python
class MyEnrichmentConnector:
    def __init__(self, config, helper):
        self.config = config
        self.helper = helper
        self.client = MyClient(...)
        self.converter_to_stix = ConverterToStix(...)
        self.stix_objects_list = []           # existing bundle, set per-request

    def entity_in_scope(self, data: dict) -> bool: ...
    def extract_and_check_markings(self, opencti_entity: dict) -> None: ...
    def _collect_intelligence(self, value: str, obs_id: str) -> list: ...
    def process_message(self, data: dict) -> str: ...
    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
```

## Order of operations matters — TLP check ALWAYS first

**Never call an external (especially paid/quota-limited) API before validating TLP.**
Check the entity's TLP against `config.max_tlp_level` via `self.helper.check_max_tlp(...)`
before doing anything else in `process_message`. This is both a data-handling rule and
a quota-protection measure — skipping it means potentially leaking sensitive entities
to a third-party API and burning quota on entities you'd reject anyway.

## Scope validation

```python
scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
entity_type = data["entity_id"].split("--")[0].lower()
return entity_type in scopes
```
`scope` in config (`connector.scope`) determines which entity types **trigger** the
connector — it does not filter what the connector is allowed to return.

## Playbook compatibility is mandatory

Connectors **must**:
1. Always return a bundle — even on error or when the entity is out of scope.
2. Include the original entity in that bundle (`data["stix_objects"]`, untouched if you
   have nothing to add).
3. Set `playbook_compatible=True` when constructing `OpenCTIConnectorHelper` — only if
   a bundle is always sent.
4. Set `"playbook_supported": true` in `__metadata__/connector_manifest.json`.

```python
if not self.entity_in_scope(data):
    if not data.get("event_type"):
        self._send_bundle(self.stix_objects_list)   # return original, unchanged
        return "Entity not in scope, returned original bundle"
    raise ValueError(f"{opencti_entity['entity_type']} is not a supported entity type")
```
On any exception during enrichment, catch it, send the **original** bundle back, and
return an error string — don't let the exception propagate and drop the bundle.

## `auto: false` for quota-based/paid sources

If the external API is metered or paid, set `connector.auto: false` in the manifest and
sample config so enrichment must be manually triggered (or driven by a Playbook with
controlled targeting) instead of firing automatically on every new observable.

## Bundle composition

Original entity/bundle + enriched or new related entities + relationships linking them
+ author + markings. Send via `self.helper.stix2_create_bundle(...)` /
`self.helper.send_stix2_bundle(...)` — never mutate objects directly via the API client
outside this flow (it bypasses confidence-level checks and deduplication).

## Reference implementation

Full example in [`docs/03-internal-enrichment-specifications.md#complete-example`](../docs/03-internal-enrichment-specifications.md#complete-example)
and the scaffold at [`templates/internal-enrichment`](../templates/internal-enrichment).
