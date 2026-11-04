# TDR: Base internal enrichment connector

## Overview

This TDR introduces `InternalEnrichmentConnector`, `BaseEnrichmentProcessor` and `EnrichmentMessage` in the `connectors.internal_enrichment` package. They rely on the `max_tlp` setting of `BaseInternalEnrichmentConnectorConfig`, added separately (#7926).

The connector class is a controller. It creates and validates the parts a connector needs, checks each message, then passes it to the right processor. A private `BundleManager`, created for each message, builds and sends its bundle, and makes sure a playbook always gets exactly one bundle. A connector only implements processors that fetch data about an entity and convert it to STIX, and return the objects.

---

## Motivation

Every internal enrichment connector re-implements the same message handling. An analysis of 10 recent manager-supported connectors (dnslytics, visionheight, greynoise, doppel-alert-takedown, shodan, proofpoint-et-intelligence, hatching-triage-sandbox, ioc-extractor, whisper, paloalto-wildfire) shows that no two of them do it the same way, and that the differences are bugs:

- **Scope**: four variants. Comparing `helper.connect_scope` with the `entity_id` prefix (the template's approach) fails for types whose STIX prefix differs from the OpenCTI type (`StixFile` → `file--`). Two connectors do not check the scope at all.
- **Check order**: five connectors check the TLP before the scope, so an out-of-scope entity with a high TLP is reported as a TLP refusal.
- **TLP setting**: three forms (`TLP:XXX`, lowercase level, unvalidated string) and four defaults. `OpenCTIConnectorHelper.check_max_tlp` raises `KeyError` on a lowercase level, which the template passes to it.
- **Playbooks**: six connectors stop the playbook on a handled case (TLP refusal, no result, source error), because they send no bundle on that path.
- **Errors**: four connectors turn every error into a successful work; handled cases are logged at ERROR; no connector uses the SDK exceptions.
- **Mutations**: two connectors modify `stix_entity` in place, which is lost outside playbooks because `stix_entity` is usually not the object inside `stix_objects` there.

A survey of all 80 internal enrichment connectors adds two findings:

- **Skips**: about 30 connectors raise on a TLP refusal and 20 raise on an out-of-scope entity, mostly because the template does. But the template catches its own error and returns, so the work ends "completed" with an ERROR log. What users see today is mixed.
- **Outcome messages** (the message stored on the work): the same few cases with many wordings. "Bundles sent" has 20 wordings, "no data" 30, "out of scope" 21, "TLP refused" 10. About 27 connectors add real detail on success (the entity value, a verdict, a score).

How `OpenCTIConnectorHelper` (pycti 7.261021.1) and the platform handle an enrichment message drives the design:

| | Manual / automatic enrichment | Playbook step |
| --- | --- | --- |
| Work | Created by the platform, closed by pycti with the callback's return value, or put in error with the exception text | None: the return value and exceptions are invisible |
| `data["event_type"]` | Set | Missing (`helper.playbook` is set instead, and reset for every message) |
| Entities sent | Entities in the connector scope (the platform filters on the scope for automatic enrichment and in the UI), but a manual request through the API (`askElementEnrichmentForConnectors`) is not filtered | Any entity: the playbook step does not filter on the scope |
| `send_stix2_bundle` | Sends the bundle to the workers | Calls the `playbookStepExecution` mutation: the platform runs the next step inside this request |

- pycti acks a message before processing it, and runs the callback in a separate thread.
- pycti checks neither the scope nor the TLP, and never sends a bundle on its own. In a playbook, sending no bundle stalls the playbook and sending two runs the next step twice.
- pycti logs a generic message on exception, without the exception text.
- `cleanup_inconsistent_bundle=True` removes references to ids missing from the bundle, so the entity to enrich must stay in the bundle when new objects refer to it.
- The platform merges properties itself. The worker upsert ignores fields absent from the bundle and adds multiple references (markings, labels, external references). In a playbook, the executor deep-merges each returned object with the previous step's object of the same id, and adds back the objects missing from the bundle. It does not deduplicate two objects with the same id within the returned bundle.
- The platform deduplicates hashed observables (files, artifacts) by their hashes. A file rebuilt with an MD5 gets another id, since the id uses the first hash in a fixed order (MD5, SHA-1, SHA-256...), but it is merged into the existing file, and its new id is kept in `x_opencti_stix_ids` (at most one id per hash algorithm).

---

## Proposed Solution

### Components

```plaintext
connectors_sdk/connectors/
├── _stix_conversion.py                 to_stix2_objects() (shared with WorkManager), to_stix_dict()
└── internal_enrichment/
    ├── enrichment_message.py           EnrichmentMessage, OpenCTIEntity, StixEntity
    ├── exceptions.py                   UnsupportedEntityError, InvalidEnrichmentMessageError
    ├── _bundle_manager.py              BundleManager (private)
    ├── base_enrichment_processor.py    BaseEnrichmentProcessor
    └── internal_enrichment_connector.py InternalEnrichmentConnector
```

- `EnrichmentMessage`: a frozen Pydantic model, built with `EnrichmentMessage.model_validate(data)` by the connector for each message. It gives the entity to enrich twice, never mixed: `enrichment_entity` (an `OpenCTIEntity`, as read from OpenCTI) and `stix_entity` (a `StixEntity`, as a STIX object). Both models only declare their `id` and their type (`entity_type`, `type`); any other field sent by pycti can be read as an attribute (e.g. `message.stix_entity.value`). It also holds `stix_objects` (the bundle containing the entity) and `from_playbook`. `OpenCTIEntity.tlp_levels` gives the TLP markings of the entity, and `EnrichmentMessage.to_log_metadata()` the context to log (`octi_id`, `octi_entity_type`, `from_playbook`).
- `BaseEnrichmentProcessor`: same lifecycle as `BaseDataProcessor` (`inject_dependencies()`, `post_init()`). It declares `handled_entity_types`, may override `can_process(message)` to filter within a type (e.g. an indicator's `pattern_type`), and implements `collect(message)` (network, no STIX) and `transform(message, data)` (STIX, no network). `process(message)` runs `transform(message, collect(message))` and returns the objects: a processor never sends anything. The message is always passed as an argument: a processor keeps no state about the current message.
- `BundleManager(helper, data)`: created by the connector for each message, from the raw message data, never seen by processors. It is a context manager that wraps the handling of the message (`with BundleManager(helper, data) as bundle_manager:`). The connector gives it the validated message in `message` (for the context of the logs) and the processor's objects in `objects`, and the manager builds and sends the bundle when the `with` block ends. `outcome` is the message stored on the work.
- `InternalEnrichmentConnector(settings, enrichment_processors)`: checks the configuration, creates the helper (with `playbook_compatible=True`) in `start()`, injects the processors' dependencies, then listens. Its callback checks the message, passes it to the processor, and stores the objects returned in the message's `BundleManager`.

### Message handling

```plaintext
invalid message?                       → error (InvalidEnrichmentMessageError, from the ValidationError)
out of scope (connector.scope)?        → skip (UnsupportedEntityError)
TLP above connector.max_tlp?           → skip (UnsupportedEntityError)
no processor can process it?       → skip (UnsupportedEntityError)
several processors can process it?       → error (ValueError)
processor.process(message): collect → transform
no objects?                            → nothing sent, outcome "No enrichment data found"
otherwise                              → send stix_objects + objects, outcome "Entity enriched with N objects"

skip:  the work completes with the reason; playbook → the original bundle is sent back
error: logged with its text, then raised again (manual/auto: the work ends in error);
       playbook → the original bundle is sent back
```

The TLP is checked before any processor sees the entity, because `can_process()` is connector code and may call the source.

`callback()` reads as follows:

```python
with BundleManager(self._helper, data) as bundle_manager:
    message = self._parse_message(data)
    bundle_manager.message = message
    self._check_scope(message)
    self._check_tlp(message)
    processor = self._select_processor(message)
    bundle_manager.objects = processor.process(message)

# The bundle is sent when the `with` block ends: the manager knows how the
# message ended (success, no data or skip)
return bundle_manager.outcome
```

### Decisions

| Question | Decision | Reason |
| --- | --- | --- |
| Connector role | A controller: create and validate the parts, check the message, pass it on | Building and sending bundles is the `BundleManager`'s job; collecting and converting is the processor's. |
| Message model | Frozen Pydantic model, with an `OpenCTIEntity` and a `StixEntity` that only declare their id and type for now | Typed access without keys. Undeclared fields stay readable as attributes. The validation copies the objects, but not the values nested in them: processors must not modify the message in place. |
| Playbook detection | `from_playbook = helper.playbook is not None`, given to the model when the message is validated | pycti resets `helper.playbook` for every message; it is the exact signal `send_stix2_bundle` uses to route the bundle. |
| Invalid message | Validated by the connector inside the `with` block: its `ValidationError` becomes an `InvalidEnrichmentMessageError`, an error like the others (logged as "Invalid enrichment message", raised to pycti, and in a playbook the `stix_objects` received are sent back when they are a list) | pycti builds `stix_entity` and `stix_objects` itself, so this should not happen, but a playbook would stall on it, silently. Validating inside the block gives it the same ways out as every other error, with no special case in the connector. The dedicated exception tells it apart from a `ValidationError` raised later by a processor (e.g. an SDK model with an invalid value). The `BundleManager` is built from the raw data, and only builds bundles: validating is the connector's job. A crash (`os._exit()`) would not replay the message, since it is already acked. |
| Bundle sending | One `BundleManager` per message, created by the connector; processors return their objects | The unit is the message, not the processor: a message gets exactly one bundle in a playbook, even when no processor handles it. As in external import, a processor only fetches and converts, and can be tested without any sender. |
| Per-message state | Kept by the `BundleManager` of the message (original objects, processor's objects, outcome) | A new manager per message: no state to reset, and nothing shared between the connector and the processors. Processors and the connector keep none. |
| Bundle content | The original `stix_objects`, then the processor's objects. An object with the id of an original object replaces it; a `Reference` is ignored | The original objects keep the references to the entity valid (`cleanup_inconsistent_bundle=True`). In a playbook, two objects with the same id would both go to the next steps: the platform does not deduplicate them. |
| Original bundle in a playbook | Sent back whenever the handling of a message ends without a bundle sent (skip, no data, failure) | Sending none stalls the playbook, and pycti has already acked the message: it will not come back. |
| When the bundle is sent | Once, when the `with` block of the `BundleManager` ends (by its private `_send()`), never through a call from the connector | The only place that sends decides between the enriched bundle, the original one or none: exactly one bundle per playbook message holds by construction, with no second send to refuse. |
| When a bundle counts as sent | As soon as `send_stix2_bundle` is called (a failure while building the bundle still sends the original one) | Once the request is sent, the connector cannot tell whether the platform ran the next step: after a timeout or a network drop while waiting for the response, sending the original bundle too could run the next step twice (e.g. an email sent twice). An error that stops the playbook is visible; a duplicated action is not. |
| Skips | `UnsupportedEntityError`: the work completes with the reason | A TLP refusal or an unsupported entity is a configured policy, not a failure. Raising would put one work in error for every RED entity in automatic mode. |
| Out of scope | A skip in every mode, logged at INFO in a playbook and at WARNING outside | In a playbook it is normal. Outside playbooks, only a request through the API can send it: a mistake of the caller, not a failure of the connector, so the work completes with the reason instead of ending in error. |
| Outcome | Always generic, owned by the `BundleManager` | The survey shows the same few cases with many wordings. |
| Several entity types | A list of processors; several may declare the same type, but exactly one `can_process()` must return `True` (`ValueError` otherwise) | The order of the processors does not matter, and overlaps are explicit in `can_process()`. |
| Startup checks | A concrete processor without `handled_entity_types`: `TypeError` when its class is defined. A scope type declared by no processor: `ConfigValidationError` when the connector is created | Each part checks its own rule, before the connector connects to OpenCTI. A scope type without processor is a configuration error (`CONNECTOR_SCOPE`), reported with the SDK configuration exception. |
| Check order | Scope, then TLP, then processor selection | No processor code runs on an entity above the max TLP. |
| `max_tlp` | `connector.max_tlp` (`CONNECTOR_MAX_TLP`), a `TLPLevel` added by #7926 (default `amber`), compared with pycti's `check_max_tlp`. The SDK converts the max TLP to the `TLP:XXX` form `check_max_tlp` expects | The TLP order is a platform rule, maintained in pycti: the SDK does not copy it. The conversion happens once in the SDK, so connectors never convert and never hit `check_max_tlp`'s `KeyError` on a lowercase level. A custom TLP marking (e.g. `TLP:EX:CHEMICAL`) is refused. |
| Scope and TLP helpers | `is_entity_in_scope()` and `is_entity_tlp_allowed()` are static methods that do not log | Connectors not built on the base can use them. `is_entity_tlp_allowed()` also accepts the max TLP as a string. |
| Merging properties | Not done by the SDK | The platform merges with its own rules (upsert, playbook executor). Rules in the SDK would duplicate them and could disagree. |
| Ids that change (e.g. a file rebuilt with an MD5) | Sent as they are | The platform deduplicates hashed observables by their hashes. Deduplication logic in the SDK could drift from the platform's. |
| Connector state | None | No analysed connector uses state; state holds checkpoints, not a cache. `BaseConnectorState` stays usable independently if needed. |
| Work management | The base never creates a work | The platform creates the work in manual/auto mode and there is none in playbooks. A connector opening its own work duplicates it. |
| Generators in `collect()`/`transform()` | Not supported | One message gives one bundle. |
| Source "not found" | The processor returns no data | The base stays independent of the HTTP client. |

### Usage

```python
class IPv4Processor(BaseEnrichmentProcessor):
    handled_entity_types = frozenset({"IPv4-Addr"})

    def post_init(self) -> None:
        self.client = MyClient(api_key=self.settings.my_source.api_key.get_secret_value())
        self.author = OrganizationAuthor(name="My Source")
        self.tlp_marking = TLPMarking(level=self.settings.my_source.tlp_level)

    def collect(self, message: EnrichmentMessage) -> dict | None:
        return self.client.get_ip(message.stix_entity.value)

    def transform(self, message: EnrichmentMessage, data: dict | None) -> list:
        if not data:
            return []
        ip = IPV4Address(value=message.stix_entity.value, score=data["score"])
        return [self.author, self.tlp_marking, ip]


InternalEnrichmentConnector(
    settings=ConnectorSettings(),
    enrichment_processors=[IPv4Processor()],
).start()
```

### Migration of existing connectors

Existing connectors keep working: the new classes are opt-in. Their own TLP settings were already moved to `connector.max_tlp` by #7926, so adopting the base removes their hand-written scope, TLP and playbook code, including their `TLP:` conversion before `check_max_tlp`. A connector that keeps its own class can replace that code with `is_entity_in_scope()` and `is_entity_tlp_allowed()`. The `connector.max_tlp` input ceiling is distinct from the marking a connector applies to the objects it creates, which stays in the connector's own settings.

---

## Advantages

- Scope, TLP and playbook handling are written and tested once, which removes the bug classes listed above from every connector built on the base.
- The static helpers `is_entity_in_scope()` and `is_entity_tlp_allowed()` fix the scope and TLP bugs of every internal enrichment connector in one change, without moving them to the base: each connector only replaces its own check with a call to the helper.
- Every connector built on the base is playbook-compatible by construction: one place sends bundles, and sends exactly one per playbook message.
- Connectors only contain source-specific code, in the same `collect()` / `transform()` shape as external import processors.
- No processor code runs on an entity above the max TLP.
- Uniform configuration (`CONNECTOR_MAX_TLP`), uniform outcome messages, and uniform logs (static messages with `octi_id`, `octi_entity_type`, `from_playbook`).
- The exception text is always logged, which pycti does not do.

---

## Disadvantages

- Behaviour change for migrated connectors: a TLP refusal, an out-of-scope or an unsupported entity now completes the work instead of failing.
- Success outcomes are generic: connectors lose their detailed messages (verdict, score, counts).
- The TLP check reads the markings stored in OpenCTI (`enrichment_entity`). In a playbook, a marking added by an earlier step and not saved yet is not seen.
- In a playbook, an entity sent back with another id (e.g. a file rebuilt with an MD5) is a second object in the bundle. The playbook's main entity keeps the old id, so the steps after the enrichment do not see the new data until ingestion merges the two by their hashes. Merging them is the job of pycti and the platform, not of the SDK or the connector.
- In a playbook, if sending the bundle fails (platform unreachable, request refused, timeout), the original bundle is not sent either, and the playbook stops at this step, with the error logged.
- Connectors that need several sends per message or their own works cannot use the base as is; none of the analysed connectors needs them legitimately.
- Processors do not receive the helper, so a connector that relies on the OpenCTI API (e.g. to pre-create labels with a color) has no supported way to reach it. This is consistent with the guideline to avoid `helper.api` in connector code, but may need a hook later.

---

## Alternatives Considered

- **Helpers only** (functions to check the scope, the TLP and to send a bundle, used by each connector's own class): rejected, since connectors could still forget to send a bundle on one path, which is the most frequent bug found. The scope and TLP checks are still offered as static helpers.
- **Bundle building and sending in the connector** (a `try`/`except` in `callback()`): rejected, since the connector must stay a controller.
- **The handling logic written in `__exit__`**: rejected for readability. The `BundleManager` is a context manager, but its `__enter__` and `__exit__` delegate to a private `@contextmanager` generator: its ways out (success, skip, invalid message, failure) are plain `except` clauses instead of `isinstance` checks and a boolean that decides whether the exception is swallowed.
- **A `handle()` method returning the context manager** (`with bundle_manager.handle():`): rejected, since the manager lives exactly as long as the message: `with BundleManager(...) as bundle_manager:` says it.
- **A bundle sender per processor, like `WorkManager`**: rejected, since a message that no processor handles still needs a bundle in a playbook.
- **One `BundleManager` for the connector, injected into the processors, which send their objects themselves**: rejected, since it shares mutable per-message state between every component, and makes processors depend on sending.
- **An explicit `send(objects)` called by the connector in the `with` block**: rejected, since the sending was then split between the connector's call and the end of the block, and a second call had to be refused with a `RuntimeError`.
- **The first processor whose `can_process()` returns `True` handles the message**: rejected, since the result depended on the order of the processors and on `can_process()` being overridden or not.
- **Running every processor that can process the entity**: rejected, since it breaks the one-bundle-per-message guarantee. A processor can call several endpoints in `collect()` instead.
- **Keeping `max_tlp` in each connector's section, read through a hook**: rejected, since it keeps three forms and four names for the same setting.
- **Raising on every skip** (the majority in today's code): rejected, see the Skips decision.
- **An out-of-scope entity as an error outside playbooks** (`EntityOutOfScopeError`): rejected, since the platform does not filter a request through the API, and the caller's mistake would put the work in error.
- **Merging the enriched entity into the entity received in the SDK** (an earlier version of this design): rejected, since the platform already merges, and the SDK rules duplicated or contradicted them. The underlying playbook issue (SDK models write `x_opencti_labels` at the top level, which pycti ignores next to the extension's labels) is fixed at its source: the SDK models also write the OpenCTI extension, in a separate change.
- **Recognizing an enriched entity under another id (shared hashes) and giving it the received entity's id**: rejected, since it brings the platform's deduplication logic into the SDK.
- **Crashing the connector on an invalid message (`os._exit()`)**: rejected, since the message is already acked and would not be replayed.

---

## References

- Related TDR: [Typing and validation of configurations with Pydantic Settings](2025-10-01-Typing_and_validation_of_configurations_with_Pydantic_Settings.md)
- Related TDR: [Generic deprecation and migration mechanism for connector configuration](2026-02-27-Deprecating_configuration_variables%20_with_BaseConnectorSettings.md)
- Related TDR: [Typing and validation of connector's state with Pydantic](2026-04-14-Typing_and_validation_of_connector_state_with_pydantic.md)
- Related TDR: [Logger independent of `OpenCTIConnectorHelper`](2026-10-16-Logger_independent_of_OpenCTIConnectorHelper.md)
- pycti 7.261021.1: `ListenQueue._process_message` and `_data_handler`, `send_stix2_bundle`, `check_max_tlp`, `OpenCTIStix2` (import of labels and external references), `OpenCTIStix2Splitter` (consulted on 2026-10-05 and 2026-10-28)
- OpenCTI platform: `domain/enrichment.js`, `domain/stixCoreObject.js`, `database/repository.js` (`connectorsForPlaybook`), `database/middleware.ts` (deduplication by hashes), `schema/identifier.js` (ids of hashed observables), `modules/playbook/playbook-components.ts`, `manager/playbookManager/playbookManager.ts` and `playbookExecutor.ts`, `utils/upsert-utils.js` (consulted on 2026-10-05 and 2026-10-28)
