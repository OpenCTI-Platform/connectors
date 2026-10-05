# TDR: Base internal enrichment connector

## Overview

This TDR introduces `InternalEnrichmentConnector`, `BaseEnrichmentProcessor` and `EnrichmentMessage` in the `connectors.internal_enrichment` package, and a `max_tlp` setting in `BaseInternalEnrichmentConnectorConfig`.

Like `ExternalImportConnector` for external import connectors, the base class owns the infrastructure of internal enrichment connectors (helper, listen loop, scope check, TLP check, bundle assembly and sending, playbook compatibility, error handling). A connector only implements processors that fetch data about an entity and convert it to STIX.

---

## Motivation

Every internal enrichment connector re-implements the same message handling. An analysis of 10 recent manager-supported connectors (dnslytics, visionheight, greynoise, doppel-alert-takedown, shodan, proofpoint-et-intelligence, hatching-triage-sandbox, ioc-extractor, whisper, paloalto-wildfire) shows that no two of them do it the same way, and that the differences are bugs:

- **Scope**: four variants. Comparing `helper.connect_scope` with the `entity_id` prefix (the template's approach) fails for types whose STIX prefix differs from the OpenCTI type (`StixFile` → `file--`). Two connectors do not check the scope at all.
- **Check order**: five connectors check the TLP before the scope, so an out-of-scope entity with a high TLP is reported as a TLP refusal.
- **TLP setting**: three forms (`TLP:XXX`, lowercase level, unvalidated string) and four defaults. `OpenCTIConnectorHelper.check_max_tlp` raises `KeyError` on a lowercase level, which the template passes to it.
- **Playbooks**: six connectors stop the playbook on a handled case (TLP refusal, no result, source error), because they send no bundle on that path.
- **Errors**: four connectors turn every error into a successful work; handled cases are logged at ERROR; no connector uses the SDK exceptions.
- **Mutations**: two connectors modify `stix_entity` in place, which is lost outside playbooks because `stix_entity` is usually not the object inside `stix_objects` there.

How `OpenCTIConnectorHelper` (pycti 7.260930.0) and the platform handle an enrichment message drives the design:

| | Manual / automatic enrichment | Playbook step |
| --- | --- | --- |
| Work | Created by the platform, closed by pycti with the callback's return value, or put in error with the exception text | None: the return value and exceptions are invisible |
| `data["event_type"]`, `data["entity_type"]` | Set | Missing (`helper.playbook` is set instead) |
| `stix_entity` | A separate dict, unless pycti had to build `stix_objects` itself | A reference to the object inside `stix_objects` |
| `send_stix2_bundle` | Sends the bundle to the workers | Calls `playbook_step_execution`: the bundle becomes the input of the next step |

- pycti checks neither the scope nor the TLP, and never sends a bundle on its own. In a playbook, sending no bundle stalls the playbook and sending two runs the next step twice.
- pycti logs a generic message on exception, without the exception text.
- `cleanup_inconsistent_bundle=True` removes references to ids missing from the bundle, so the enriched entity must stay in the bundle.
- The playbook executor deep-merges the returned bundle with the previous step's bundle (same id: merged; missing objects: added back).
- The worker upsert ignores fields absent from the bundle and only adds multiple references (markings, labels, external references).

---

## Proposed Solution

### Components

```plaintext
connectors_sdk/connectors/
├── _stix_conversion.py              to_stix2_objects(), shared with WorkManager
└── internal_enrichment/
    ├── enrichment_message.py        EnrichmentMessage
    ├── base_enrichment_processor.py BaseEnrichmentProcessor
    └── internal_enrichment_connector.py InternalEnrichmentConnector
```

- `EnrichmentMessage`: a frozen dataclass built for each message. It exposes only fields that are reliable in every mode: `entity_id`, `entity_type` (from `enrichment_entity`, set in playbooks too and matching OpenCTI type names), `enrichment_entity`, `stix_entity`, `stix_objects`, `tlp_levels` (every TLP marking), `is_playbook`, and `entity_copy()` (a deep copy of `stix_entity`, safe to modify). A dataclass and not a Pydantic model: the data comes from pycti, is not user input, and must not be copied on validation.
- `BaseEnrichmentProcessor`: same lifecycle as `BaseDataProcessor` (`inject_dependencies()`, `post_init()`). It declares `entity_types`, may override `supports(message)` to filter within a type (e.g. an indicator's `pattern_type`), and implements `collect(message)` (network, no STIX) and `transform(data, message)` (STIX, no network). It never sends bundles and holds no per-message state.
- `InternalEnrichmentConnector(settings, enrichment_processors)`: creates the helper with `playbook_compatible=True` in `start()`, injects the processors' dependencies, then listens. Its callback handles each message.

### Message handling

```plaintext
out of scope (connector.scope, case-insensitive)?   → skip (INFO)
no processor supports the entity?                    → skip (WARNING)
an entity TLP above connector.max_tlp?               → skip (WARNING), before any call to the source
objects = processor.transform(processor.collect(message))
no objects?                                          → skip (INFO)
otherwise → send stix_objects + objects, an object sharing an id with an original object replacing it

skip:  playbook → send the original bundle back; manual/auto → send nothing, the work completes with the reason
error: log the exception text at ERROR; playbook → send the original bundle back; re-raise (manual/auto: work in error)
```

Bundles are sent with `cleanup_inconsistent_bundle=True`. The bundle is serialized before anything is sent, so an object that cannot be serialized goes through the error path. A bundle is never sent twice for a message: a failure while sending is logged and re-raised, not retried. A failure while sending the original bundle back after an error is logged, and the original error is re-raised.

### Decisions

| Question | Decision | Reason |
| --- | --- | --- |
| Connector state | None | No analysed connector uses state; state holds checkpoints, not a cache. `BaseConnectorState` stays usable independently if needed. |
| Work management | No `WorkManager`, the base never creates a work | The platform creates the work in manual/auto mode and there is none in playbooks. A connector opening its own work duplicates it. |
| Several entity types | A list of processors, the first whose `supports()` returns `True` handles the message | Consistent with `ExternalImportConnector`. One processor may declare several types; overlapping processors are allowed (specific ones first). |
| Startup checks | Empty `entity_types`: error. Scope type handled by no processor, or type shadowed by an earlier processor that does not override `supports()`: WARNING | Catch mismatches between configuration and code before the first message. |
| Skips in manual/auto mode | The work completes with the reason; it is not an error | Out of scope, unsupported or above max TLP are policy outcomes, not failures. |
| `max_tlp` | `connector.max_tlp` (`CONNECTOR_MAX_TLP`), `TLP:CLEAR` to `TLP:RED`, default `TLP:AMBER`; a lowercase level or a level without the `TLP:` prefix is normalized | A generic policy like `scope` and `auto`, with one environment variable for every connector and the form `check_max_tlp` expects. `TLP:AMBER` is the most common default today. |
| Playbook detection | `helper.playbook is not None` | The exact signal `send_stix2_bundle` uses to route the bundle; equivalent to a missing `event_type`. |
| Enriched entity | Replaced by id in the bundle, no merge | The playbook executor merges with the previous step's bundle, and the worker upsert never removes data absent from the bundle. |
| Generators in `collect()`/`transform()` | Not supported | One message gives one bundle. |
| Source "not found" | The processor returns no data, the base skips | The base stays independent of the HTTP client. |

### Usage

```python
class IPv4Processor(BaseEnrichmentProcessor):
    entity_types = frozenset({"IPv4-Addr"})

    def post_init(self) -> None:
        self.client = MyClient(api_key=self.settings.my_source.api_key.get_secret_value())
        self.author = OrganizationAuthor(name="My Source")
        self.tlp_marking = TLPMarking(level=self.settings.my_source.tlp_level)

    def collect(self, message: EnrichmentMessage) -> dict | None:
        return self.client.get_ip(message.stix_entity["value"])

    def transform(self, data: dict | None, message: EnrichmentMessage) -> list:
        if not data:
            return []
        entity = message.entity_copy()
        entity["x_opencti_score"] = data["score"]
        return [self.author, self.tlp_marking, entity]


InternalEnrichmentConnector(
    settings=ConnectorSettings(),
    enrichment_processors=[IPv4Processor()],
).start()
```

### Migration of existing connectors

Existing connectors keep working: `max_tlp` has a default and the new classes are opt-in. A connector adopting the base moves its own TLP setting (e.g. `SHODAN_MAX_TLP`) to `connector.max_tlp` with `DeprecatedField(new_namespace="connector", new_namespaced_var="max_tlp")`. The `connector.max_tlp` input ceiling is distinct from the marking a connector applies to the objects it creates, which stays in the connector's own settings.

---

## Advantages

- Scope, TLP and playbook handling are written and tested once, which removes the bug classes listed above from every connector built on the base.
- Every connector built on the base is playbook-compatible by construction.
- Connectors only contain source-specific code, in the same `collect()` / `transform()` shape as external import processors.
- Uniform configuration (`CONNECTOR_MAX_TLP`) and uniform logs (static messages with `entity_id`, `entity_type`, `is_playbook`, `processor` context).
- The exception text is always logged, which pycti does not do.

---

## Disadvantages

- Behaviour change for migrated connectors that raise today on out-of-scope entities or TLP refusals: the work now completes with the reason instead of failing.
- `connector.max_tlp` appears in the generated schema of a connector that is not migrated yet (at its next regeneration) while the connector still reads its own setting. Connectors must be migrated when they adopt the base, or in one batch.
- Connectors that need several sends per message or their own works cannot use the base as is; none of the analysed connectors needs them legitimately.
- Processors do not receive the helper, so a connector that relies on the OpenCTI API (e.g. to pre-create labels with a color) has no supported way to reach it. This is consistent with the guideline to avoid `helper.api` in connector code, but may need a hook later.
- `ConnectorLogger` is imported from `connectors.external_import` until the logger work (PR #7102) settles where it lives.

---

## Alternatives Considered

- **Helpers only** (functions to check the scope, the TLP and to send a bundle, used by each connector's own class): rejected, since connectors could still forget to send a bundle on one path, which is the most frequent bug found.
- **A single processor per connector with internal dispatch**: rejected as the only option, as most connectors already dispatch by type. It stays possible: one processor may declare every type.
- **Running every processor that supports the entity**: rejected, since it breaks the one-bundle-per-message guarantee. A processor can call several endpoints in `collect()` instead.
- **Keeping `max_tlp` in each connector's section, read through a hook**: rejected, since it keeps three forms and four names for the same setting.
- **Raising on skips in manual/auto mode** (the current majority behaviour): rejected, since a skip is a configured policy, not a failure, and it is invisible in playbooks anyway.
- **Merging the enriched entity with the original instead of replacing it**: rejected as unnecessary, given the playbook executor merge and the additive worker upsert.

---

## References

- Related TDR: [Typing and validation of configurations with Pydantic Settings](2025-10-01-Typing_and_validation_of_configurations_with_Pydantic_Settings.md)
- Related TDR: [Generic deprecation and migration mechanism for connector configuration](2026-02-27-Deprecating_configuration_variables%20_with_BaseConnectorSettings.md)
- Related TDR: [Typing and validation of connector's state with Pydantic](2026-04-14-Typing_and_validation_of_connector_state_with_pydantic.md)
- pycti `OpenCTIConnectorHelper` (7.260930.0): `ListenQueue._data_handler`, `send_stix2_bundle`, `check_max_tlp` (consulted on 2026-10-05)
- OpenCTI platform: `domain/enrichment.js`, `domain/stixCoreObject.js`, `modules/playbook/playbook-components.ts`, `utils/upsert-utils.js` (consulted on 2026-10-05)

---
