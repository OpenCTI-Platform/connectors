# TDR: Data providers (proof of concept)

## Overview

This TDR records a proof of concept for data providers: components that call a
source API and return the input of a converter, so that a provider and a converter
can be chained. It complements the converter abstraction
(`2026-10-27-Converter_abstraction.md`).

The PoC adds `connectors_sdk.providers`:

- `AbstractDateRangeProvider` and `AbstractByIdProvider`;
- `CrowdStrikeActorDateRangeProvider`, built on falconpy (optional extra `crowdstrike`);
- `ShodanInternetDbHostByIdProvider`, built on the SDK's `BaseClientApi`.

**No connector was changed, and `AbstractAdditionalStixProvider` was left as is.**

---

## Motivation

Converters are pure: something else has to call the source and build their typed
input. Today each connector does it its own way:

- CrowdStrike pages actors by `last_modified_date` inside `ActorImporter`, then calls
  MITRE once per actor.
- Shodan InternetDB wraps `requests` in its own client, with no timeout.

A provider whose output type is the converter's input type gives one shape to this
code, and lets mypy check that a provider and a converter fit.

---

## Proposed Solution

```python
T = TypeVar("T", bound=BaseModel)  # the converter's input type

class AbstractDateRangeProvider(_ClassLoggerMixin, ABC, Generic[T]):
    @abstractmethod
    def get_data(self, since: datetime, limit: int) -> dict[datetime, list[T]]: ...

class AbstractByIdProvider(_ClassLoggerMixin, ABC, Generic[T]):
    @abstractmethod
    def get_data(self, ids: list[str]) -> dict[str, T]: ...
```

| Rule | Choice |
|---|---|
| Item type | The input model of the converter fed, so `AbstractDateRangeProvider[X]` chains with `AbstractConverter[X]` |
| Date range result | Items grouped by timezone-aware date; `max(result)` is the next `since` |
| `since` | Inclusive (`>=`); the date the source uses to report changes |
| `limit` | Passed to the source; one list request per call, no pagination |
| Extra calls | Allowed per item (CrowdStrike MITRE ids) |
| By id result | Keyed by `str` id; an id with no data is absent |
| Failures | `DataRetrievalError` chained to the cause; never an empty or partial result |
| Invalid item | Skipped and logged at WARNING, so one bad item never blocks the checkpoint |
| Naming | `<Provider><Payload>DateRangeProvider` / `<Provider><Payload>ByIdProvider`, checked in `__init_subclass__` |

Chaining is done by hand for now, as in the tests:

```python
result = provider.get_data(since=checkpoint, limit=50)
objects = [o for items in result.values() for i in items for o in converter.transform(i)]
checkpoint = max(result, default=checkpoint)
```

### Why a dict keyed by date

A list does not say where to resume, and a `dict[datetime, T]` loses items sharing a
date: CrowdStrike dates are whole seconds, so a bulk edit puts many actors on one key.
`dict[datetime, list[T]]` keeps them and gives the checkpoint without knowing the item
type.

### Why `>=`

With one call per `get_data` and `limit` passed to the API, the API can cut a group of
items sharing a date. `>` would skip the rest of that group on the next call; `>=`
fetches it again. Items fetched twice are harmless because SDK models have
deterministic ids.

### Dependencies

- falconpy is an optional extra (`connectors-sdk[crowdstrike]`, pinned like the
  connector, 1.6.5) and part of the `test` extra so mypy checks the provider. It ships
  `py.typed`. `connectors_sdk.providers` never imports it; the CrowdStrike provider is
  imported from `connectors_sdk.providers.crowdstrike`.
- `providers/crowdstrike/*` is excluded from the 100% coverage gate (PoC decision). The
  tests nevertheless cover it fully (56/56 statements), so the exclusion can be dropped.
- Shodan uses `BaseClientApi`: timeout, retries on 429 and 5xx, rate limiting and
  `ApiNotFoundError` on 404, none of which the connector's client has.

---

## Results

### Comparison with the CrowdStrike connector

A script fed the same fake CrowdStrike source (FQL filter, ascending sort, offset and
limit) to the connector's real `ActorImporter._fetch_actors` and to the provider,
calling the provider until it stopped advancing.

| Case | Connector | Provider (limit 50) |
|---|---|---|
| 120 actors, distinct dates | 120 in 1 run (3 pages) | 120 in 3 calls, plus 1 call returning nothing new |
| 3 actors in one second, split by the limit | 52 | 52: the split second is fetched again |
| An actor modified later in the same second as the saved checkpoint | **Lost** (`>` filter) | Imported (`>=`) |
| 60 actors in one second | 61 | **50, checkpoint stuck** (expected, see below) |
| MITRE ids | `T1059.001` created from `actor-1_TA0002_T1059.001` | Same raw ids; the converter filters techniques |
| MITRE query answers 403 | Logged, actor imported without techniques | `DataRetrievalError`, the call fails |

### Findings

- **Stuck checkpoint.** When more items share one date than `limit`, every call
  returns the same items and `max(result)` stays at `since`. A test documents it. With
  CrowdStrike (whole seconds, `limit` up to 5,000) it needs a bulk edit larger than
  `limit` in one second. The caller can detect it without an extra call: the
  checkpoint did not advance and the call returned `limit` items.
- **`>=` fixes a connector gap.** The connector saves the max date of a run and
  filters `>` on the next run, so an actor modified later in that same second is never
  imported.
- **Re-fetch cost.** Each call returns at least the items at `since` again, so a call
  with nothing new still returns (and sends) the last date's items.
- **One call per run catches up slower.** A backlog of `n` items needs about `n / limit`
  runs instead of one paginated run.
- **MITRE errors are no longer hidden.** The connector turns a MITRE failure into "no
  technique"; the provider fails the call, so the checkpoint does not move past actors
  imported without their techniques.
- **N+1 MITRE calls.** Same as the connector. falconpy documents
  `query_mitre_attacks(ids=[...])` with several values and the returned ids are
  prefixed by the actor slug, which could make it one call. Not confirmed: falconpy's
  examples use slugs, the connector passes numeric ids.
- **FQL `>=`** is documented but only tested with a fake client.

---

## Advantages

- One shape for fetching code, typed with the converter it feeds: a mismatched pair
  fails mypy.
- The checkpoint rule is the same for every date range provider (`max(result)`), with
  no knowledge of the item type.
- Providers are testable with a fake client, converters without any client.
- Shodan gets a timeout, retries and rate limiting from the SDK client for free.

## Disadvantages

- Without pagination, a backlog takes several runs, and a date with more items than
  `limit` blocks the checkpoint.
- Every caller still writes the chaining loop and the checkpoint handling.
- The CrowdStrike provider hides N+1 calls behind "one call".
- falconpy enters the SDK's dependency metadata, even as an extra.

---

## Alternatives Considered

- **One `AbstractProvider.get_data(after_date, limit)`**: does not fit lookups by id
  (Shodan), hence two contracts.
- **`get_data` returning `list[T]`**: no generic way to compute the checkpoint.
- **`dict[datetime, T]`**: loses items sharing a date.
- **Completing or dropping the last date group inside the provider**: rejected for
  simplicity; `>=` gives the same guarantee without the provider counting items.
- **Pagination inside `get_data`**: no stuck checkpoint and one run per backlog, but
  results can grow large; deferred.
- **A `Protocol` for the CrowdStrike client** (as in the PDF provider): keeps falconpy
  out of the SDK, but the PoC was asked to use the real library.
- **Splitting MITRE into its own `AbstractByIdProvider`**: tests both contracts
  together, but needs a composition piece that does not exist yet.

---

## Next Steps

- A chain piece (provider plus converter plus checkpoint), then a `BaseDataProcessor`
  adapter for `ExternalImportConnector`.
- Detection of a stuck checkpoint, or pagination.
- A CrowdStrike MITRE by id provider, batched if `ids=[...]` works.
- The report PDF with `str` ids (the file name comes from the report name), and the
  place of `AbstractAdditionalStixProvider`.

---

## References

- `connectors_sdk/providers/`
- `tests/test_providers/`
- `external-import/crowdstrike/src/crowdstrike_feeds_connector/actor/importer.py`
- `internal-enrichment/shodan-internetdb/src/shodan_internetdb/client.py`
- `TDRs/2026-10-27-Converter_abstraction.md`, `TDRs/2026-10-27-Additional_stix_provider.md`
