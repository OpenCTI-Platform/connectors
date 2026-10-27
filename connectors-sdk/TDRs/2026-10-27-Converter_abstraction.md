# TDR: Converter abstraction (proof of concept)

## Overview

This TDR records a proof of concept for a shared converter contract in `connectors-sdk`:
one class per provider payload, named `<Provider><Payload>Converter`, that turns a
validated Pydantic input model into SDK OpenCTI models.

The PoC adds `connectors_sdk.converters` (`AbstractConverter`, `ConversionError`) and
ports five payloads from five connectors. **No connector was changed**: the converters
are not wired anywhere. This document records what fitted, what did not, and where
provider converters should live.

---

## Motivation

Every connector converts a third-party payload to STIX, with no shared shape:

- 85 connectors use a single template-derived `ConverterToStix` class that mixes
  per-run context (helper, author, marking) with per-item conversion.
- A few split conversion per payload, each in its own way: `CensysConverter`
  (fetches its own data), CrowdStrike `*BundleBuilder` classes (stix2 objects,
  inputs in the constructor).

Conversion code is therefore hard to test in isolation and often has side effects
(OpenCTI API calls, `now()` in ids) that a uniform contract would make visible.

---

## Proposed Solution

```python
# connectors_sdk/converters/base.py
InputT = TypeVar("InputT", bound=BaseModel)

class AbstractConverter(ABC, Generic[InputT]):
    def __init__(self, author: BaseAuthorEntity, markings: list[TLPMarking]) -> None: ...

    @abstractmethod
    def transform(self, input: InputT) -> list[BaseIdentifiedObject]: ...
```

Rules of the contract:

| Rule | Choice |
|---|---|
| Input | One Pydantic model per payload, declared as the type parameter (strict mypy rejects narrowing a `BaseModel` parameter in subclasses). |
| Output | SDK OpenCTI models (`BaseIdentifiedObject`): deterministic ids by construction. |
| Per-run context | Constructor (`author`, `markings`, provider flags such as `feed_type`). |
| Per-item context | Input model (e.g. the enriched observable for an enrichment). |
| Author and markings | Referenced by every object, never returned: the caller adds them once per bundle. |
| Side effects | None: no network, no state, no OpenCTI calls. |
| Errors | `ConversionError(UseCaseError)`, raised `from` the cause; the caller skips the item. |
| Naming | `__init_subclass__` rejects a concrete subclass whose name does not end with `Converter`. |
| Composition | A converter builds sub-converters with its own context and extends its result with theirs. |

Proof-of-concept converters (`connectors_sdk/converters/<provider>/`):

| Converter | Source | Fit |
|---|---|---|
| `VulnerabilityLookupCveConverter` | `external-import/vulnerability-lookup` | Direct port, no workaround. |
| `WhoisFreaksThreatFeedConverter` | `external-import/whoisfreaks` | `feed_type` in the constructor; custom properties dropped (SDK gap). |
| `ShodanInternetDbHostConverter` | `internal-enrichment/shodan-internetdb` | Enriched observable in the input; labels by re-emitting the observable. |
| `RansomwareLiveVictimConverter` | `external-import/ransomwarelive` | OpenCTI lookups, group resolution and domain extraction had to move or change. |
| `CrowdStrikeActorConverter` (+ `CrowdStrikeLocationConverter`, `CrowdStrikeSectorConverter`) | `external-import/crowdstrike` | Composition works; output type needs narrowing; no `confidence`. |

---

## Results

### Parity with the existing connectors

A throwaway script ran each connector's own conversion code and the new converter on
the same fixtures (OpenCTI lookups stubbed to "not found") and compared the
`(type, STIX id)` sets, author and markings excluded.

| Provider | Common / connector / SDK | Differences and reasons |
|---|---|---|
| Vulnerability-Lookup | 2 / 2 / 2 | None. |
| CrowdStrike actor | 47 / 47 / 47 | None. |
| WhoisFreaks | 3 / 4 / 4 | **Note**: the connector computes `Note.generate_id(None, content)` without the abstract; the SDK `Note` hashes its abstract too. Content is identical. |
| Shodan InternetDB | 7 / 8 / 8 | **Note**: the connector passes `now()` to `Note.generate_id`, so its id changes on every run (forbidden by `AGENTS.md`). The converter's note id is stable. |
| Ransomware.live | 10 / 16 / 16 | **Domain name + its `belongs-to`**: the connector reduces hosts to the registered domain with `tldextract` (`www.acme.example.com` → `example.com`); the converter keeps the host. **3 dated `targets` + the report**: Ransomware.live dates have no timezone; the connector hashes naive datetimes into pycti ids, SDK models only accept aware datetimes (read as UTC), so the ids differ. |

Migrating a connector to its converter would therefore keep every id for
Vulnerability-Lookup and CrowdStrike, and create one-off duplicates for the
WhoisFreaks notes and the Ransomware.live reports and dated relationships.

### Gaps in SDK models

- **No custom properties.** WhoisFreaks sets `x_whoisfreaks_domain`, `_threat_type`,
  `_confidence`, `_first_seen`, `_last_seen`, `_no_of_threat_matched_pivots` and
  `_feed_type` on its domain and indicator; SDK models (`extra="forbid"`) cannot carry them.
- **No `confidence`.** CrowdStrike sets it on intrusion sets, malware and relationships.
  The planned `confidence_level` constructor argument was dropped because it could
  not be applied.
- **No in-place update of an existing observable.** Shodan adds labels to the enriched
  observable in place. The converter re-emits `IPV4Address(value, labels=...)` (same
  id) when there are tags; by the contract it also carries the converter's author and
  markings, which OpenCTI merges onto the existing observable.
- **Naive datetimes.** See Ransomware.live above.
- **Enum values.** `Ransomware-report` (report type) and `geopolitical` (motivation)
  are not in the SDK enums and raise a `UserWarning` from the permissive enums.

### Friction in the contract

- **Output type too wide for composition.** Sub-converters return
  `list[BaseIdentifiedObject]`, but `Relationship.source`/`target` need
  `BaseIdentifiedEntity`, so `CrowdStrikeActorConverter` narrows with an `isinstance`
  filter. A second type parameter (`AbstractConverter[InputT, OutputT]`) would remove it.
- **Input models in the SDK cannot keep the API casing.** Ruff `N815` forbids camelCase
  attributes, so Vulnerability-Lookup fields are snake_case with API aliases, unlike the
  template's convention.
- **Unreachable error path.** For Ransomware.live no valid input reaches a
  `ValidationError`; the `ConversionError` wrapper is kept as a safety net and tested
  with a monkeypatch.

### Conversion code that was not pure

The contract surfaced side effects and hidden inputs in today's conversion code:

- Ransomware.live resolves countries, sectors and attack patterns through `helper.api`
  during conversion and resolves the group entry from the `/groups` feed. In the
  converter, names come from the input and resolution is the caller's job.
- Ransomware.live's domain extraction depends on `validators` and `tldextract` (which
  downloads the public suffix list); the converter uses the standard library.
- CrowdStrike strips HTML with `lxml`; the converter uses `html.parser`.
- Shodan InternetDB sets `start_time=now` and `stop_time=now + 60 days` on its
  `related-to` relationships. Their ids do not include the times, but the output
  changes on every run; the converter drops both, losing the 60-day validity window.
- CrowdStrike resolves MITRE techniques with an extra API call, so the input is
  `CrowdStrikeActorInput(actor, mitre_attack_ids)`; malware is derived from the actor.

### Defects found in the connectors

- Shodan InternetDB: note id built from `now()` (one new note per enrichment).
- Ransomware.live: `safe_datetime(None)` raises although its docstring says it returns
  `None`, so a victim without `discovered` aborts its bundle.
- CrowdStrike: malware built from a `set`, so object order changes between runs (ids do not).

### Duplication

The PoC copies or rewrites provider code in the SDK: input models
(`ThreatFeedRecord`, `ShodanResult`, which is a `pydantic.v1` model in the connector)
and CrowdStrike helpers (`timestamp_to_datetime`, `normalize_start_time_and_stop_time`,
`extract_actor_intrusion_set_labels`, alias and motivation mapping,
`create_regions_and_countries_from_entities`, `create_sectors_from_entities`,
technique-id parsing).

---

## Advantages

- One shape for conversion: pure, typed in and out, testable from a JSON fixture
  without a helper, a platform or mocks.
- Deterministic ids by construction; side effects in conversion become visible.
- Composition lets one payload converter reuse another (locations, sectors).
- Item-level failures are isolated with an error type callers already handle.

## Disadvantages

- SDK model gaps (custom properties, `confidence`, observable updates) block a
  faithful port for some connectors.
- Migrating changes some ids (naive datetimes, note ids), which creates one-off
  duplicates in OpenCTI.
- Provider converters in the SDK duplicate connector models and ship provider code,
  and its dependencies, to every connector.

---

## Alternatives Considered

- **`transform(self, input: BaseModel)` without generics**: rejected, subclasses
  cannot narrow the parameter type under strict mypy.
- **A `Protocol` instead of an ABC**: rejected, no shared constructor and no naming hook.
- **Extra `transform` arguments for per-item context**: rejected, it breaks the uniform
  signature; the input model carries it instead.
- **Returning `stix2` objects**: rejected, random ids become possible again.

---

## Recommendation

1. Keep `AbstractConverter` and `ConversionError` in `connectors-sdk`, and add an output
   type parameter (`AbstractConverter[InputT, OutputT]`).
2. Keep **provider converters in their connectors**, not in the SDK: they depend on
   provider libraries (`tldextract`, `lxml`), change with provider APIs, and their input
   models already live there. The SDK could host shared helpers (HTML to text, activity
   date normalisation) if several connectors need them.
3. Before migrating connectors, close the SDK model gaps: custom properties,
   `confidence`, and a way to update an existing observable.
4. Migrate first the connectors whose parity is complete (Vulnerability-Lookup,
   CrowdStrike actor). For the others, accept the listed id changes explicitly.

---

## References

- `connectors_sdk/converters/` and `tests/test_converters/`
- `templates/external-import/src/template_client/models.py` (input models at the API boundary)
- `internal-enrichment/censys-enrichment/src/censys_enrichment/converters/` (prior art)
- `TDRs/2025-06-06-Rely_on_pydantic_OCTI_models.md`
- `TDRs/2025-06-12-Error_and_warning_handling_tools.md`

---
