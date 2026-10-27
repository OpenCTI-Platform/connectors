# TDR: Additional STIX provider (proof of concept)

## Overview

This TDR records a proof of concept for `AdditionalStixProvider`, a contract for
components that fetch additional data for one id or a list of ids from a source and
return it as SDK OpenCTI objects. It complements the converter abstraction
(`2026-10-27-Converter_abstraction.md`): converters stay pure, providers own the
network calls a conversion needs.

The first case is the CrowdStrike report PDF. The PoC adds:

- an `Artifact` observable model;
- `connectors_sdk.additional_stix_providers` (`AbstractAdditionalStixProvider`);
- `CrowdStrikeReportPdfAdditionalStixProvider` with its `CrowdStrikeReportPdfConverter`.

**No connector was changed.**

---

## Motivation

The converter PoC found conversion code that fetches data while converting: report
PDFs, MITRE techniques and related IOCs in CrowdStrike, OpenCTI lookups and group
resolution in Ransomware.live.

The report PDF shows the problems:

- `ReportImporter._get_report_pdf` downloads one PDF per report, and `ReportFetcher`
  duplicates the same logic with its own cache.
- `ReportsAPI.get_report_pdf` logs an API error and returns the response dict. The
  importer treats every dict as "no PDF", so a permission or server error silently
  drops the file.
- falconpy returns `b""` for an empty binary body. The connector checks
  `isinstance(download, dict)` only, so it would attach an empty PDF.

---

## Proposed Solution

```python
KeyT = TypeVar("KeyT", bound=Hashable)

class AbstractAdditionalStixProvider(ABC, Generic[KeyT]):
    def __init__(self, author, markings, cache: bool = False) -> None: ...
    def get(self, id: KeyT) -> list[BaseIdentifiedObject] | None: ...
    def get_many(self, ids: Iterable[KeyT]) -> dict[KeyT, list[BaseIdentifiedObject]]: ...
    def clear_cache(self) -> None: ...
    @abstractmethod
    def _fetch(self, id: KeyT) -> list[BaseIdentifiedObject] | None: ...
```

| Rule | Choice |
|---|---|
| Result for one id | A list of objects when found, `None` when the source has nothing |
| Source failure | `DataRetrievalError`, chained to the cause; never treated as "nothing" |
| Several ids | `get_many` fetches each distinct id once and groups results by id; ids returning `None` are left out |
| Author and markings | Constructor; referenced by the objects, never returned |
| Cache | Opt-in, per instance, stores `None` too, never stores failures; `clear_cache()` at the start of a run |
| Conversion | Delegated to a pure `AbstractConverter` (`CrowdStrikeReportPdfConverter`) |
| Naming | `<Provider><Payload>AdditionalStixProvider`, checked in `__init_subclass__` |
| Source client | A `Protocol`, so the SDK does not depend on falconpy |

The CrowdStrike key is `CrowdStrikeReportKey(id, name)`: the PDF endpoint does not
return the report name, and the file name is built from it.

### PDF as a shared Artifact

The PDF becomes a STIX 2.1 `artifact` (`payload_bin`, `mime_type`, `hashes`), and the
file name is passed as `x_opencti_additional_names`. pycti uploads the payload as the
Artifact's file, named after the first additional name.

| | Today: `x_opencti_files` on the Report | Artifact |
|---|---|---|
| Where the PDF appears | The report's Files tab | An Artifact observable, to be referenced in the report content |
| Import-file connectors | Triggered unless `no_trigger_import` | No equivalent setting |
| Same PDF in two reports | Uploaded twice | Stored once |
| Standalone STIX object | No | Yes |

**OpenCTI deduplicates artifacts on `hashes`, then `url`, not on `payload_bin`.** See
`opencti-graphql/src/schema/identifier.js` (local checkout of 2026-10-16), where the
code comment gives volume as the reason for leaving `payload_bin` out. The `Artifact`
model therefore always sets a SHA-256 computed from the content. The STIX id produced
by stix2 (from `hashes` and `payload_bin`) is also deterministic, but OpenCTI computes
its own id from the hashes.

---

## Results

### Comparison with the connector

The same bytes and report name went through `create_file_from_download` and through
the provider with a fake client, for three cases (a plain name, double spaces, a
lower-case name). Content, MIME type and file name are equal in all cases. The only
difference is `no_trigger_import`, which has no Artifact equivalent.

### Response mapping

From falconpy 1.6.5 (`_util/_functions.py`, `_result/_result.py`):

| CrowdStrike response | falconpy returns | Provider |
|---|---|---|
| Binary body | `bytes`, whatever the status code | One artifact |
| Empty binary body | `b""` | `None` |
| JSON body (errors) | `{"status_code", "headers", "body"}` | `None` for 404, `DataRetrievalError` otherwise |
| Exception raised by the client | — | `DataRetrievalError` chained to it |

**Assumption:** 404 means "this report has no PDF". falconpy does not define it,
the CrowdStrike API reference is not public, and a web search found nothing
authoritative. This must be confirmed against a real tenant before use.

Because falconpy returns any binary body as bytes whatever the status, other public
integrations (Kestra's CrowdStrike plugin, falcon-mcp) check the `%PDF` magic bytes
before trusting the payload. This PoC does not; it is a recommended follow-up.

### Other findings

- stix2 validates hash formats inside `to_stix2_object`, so an invalid hash raises a
  stix2 exception rather than a pydantic `ValidationError`. The existing `File` model
  behaves the same.
- The naming check is copied from `AbstractConverter`. Both could share one helper.

---

## Advantages

- "Not found" and "failure" are distinct, so a permission or server error is no longer
  silent.
- One place for per-id fetching, deduplication and caching, instead of per-connector
  code (`_get_report_pdf` and `ReportFetcher` today).
- The conversion stays pure and testable; the provider is testable with a fake client.
- The same PDF is stored once across reports.

## Disadvantages

- The PDF leaves the report's Files tab, and `no_trigger_import` cannot be expressed:
  a visible change for users.
- The caller must still put each artifact in its report's `object_refs`. No report
  converter exists yet.
- PDFs are held in memory and base64-encoded into bundles, as today.

---

## Alternatives Considered

- **Return typed data (`CrowdStrikeReportPdf`) instead of STIX**, and keep building
  `x_opencti_files` in a report converter. This keeps today's UX but does not return
  STIX objects; it remains the fallback if the Artifact UX is rejected.
- **Return `[]` for "nothing"**: replaced by `None` (user decision), so "found but
  converts to nothing" and "not found" stay distinct.
- **A flat list from `get_many`**: rejected, the caller needs the objects of each id.
- **Key on the report id only** (file name `crowdstrike-report-<id>.pdf`): simpler,
  but changes the file name users see.

---

## Next candidates

| Case | Key | Notes |
|---|---|---|
| CrowdStrike actor MITRE techniques (`query_mitre_attacks`) | actor id | Feeds `CrowdStrikeActorInput.mitre_attack_ids` today |
| CrowdStrike related IOCs of a report | report name | Paginated, depends on API scopes |
| CrowdStrike `ReportFetcher` (YARA, Snort/Suricata, indicators) | report code | A report provider composed with the PDF provider, cache enabled |
| Ransomware.live group entry | group name | `get_many` can fetch `/groups` once |
| Ransomware.live country and sector lookups | name | Backed by OpenCTI (`helper.api`), which `AGENTS.md` discourages |

---

## References

- `connectors_sdk/additional_stix_providers/`, `connectors_sdk/models/artifact.py`
- `connectors_sdk/converters/crowdstrike/report_pdf.py`
- `external-import/crowdstrike/src/crowdstrike_feeds_connector/report/importer.py`
- `external-import/crowdstrike/src/crowdstrike_feeds_services/utils/report_fetcher.py`
- `TDRs/2026-10-27-Converter_abstraction.md`

---
