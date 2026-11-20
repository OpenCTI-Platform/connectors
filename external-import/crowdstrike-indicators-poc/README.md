# CrowdStrike indicators: proof of concept

> **Status: proof of concept, command line only.** Not a connector: it does
> not talk to OpenCTI and keeps no state between runs.

This folder tests a new organization for connectors, built from small
contracts that do not depend on OpenCTI:

1. an extractor: typed, validated CrowdStrike Falcon Intelligence indicators,
   run from the command line against the real API, so the indicator model can
   be refined from actual data, each with the actors it names, looked up
   through an enricher;
2. transformers, chained:
   - each indicator converted into one STIX 2.1 indicator that loses nothing
     of the source data;
   - that indicator bundled with one Malware per family it names, and the
     `indicates` relationships linking them;
   - the MITRE ATT&CK AttackPatterns its labels name added to the bundle, with
     their `indicates` relationships, from a local ATT&CK dataset;
   - the whole turned into a standard STIX 2.1 bundle, ready for a STIX
     consumer;
3. a loader: each STIX bundle delivered to a destination, for now a JSON file
   per bundle;
4. a generic connector assembling the three, running them on a schedule.

## Layout

```
src/
  shared/                     contracts, independent of any source
    extractor.py              AbstractExtractor[T: BaseModel]
    enricher.py               AbstractEnricher[T: BaseModel]
    transformer.py            AbstractTransformer[InputType, OutputType]
    loader.py                 AbstractLoader (loads stix2 Bundles)
    record_to_file.py         RecordToFile
    connector.py              Connector, CycleResult
    factory.py                AbstractConnectorFactory[S: BaseSettings],
                              ConnectorConfigurationError
    type_arguments.py         declared_types, reads a component's type arguments
    errors.py                 SourceAPIError, ItemValidationError,
                              ItemConversionError
    cli.py                    the connector-cli command, for any factory
  crowdstrike_indicators/     CrowdStrike implementation
    factory.py                CrowdStrikeSettings, CrowdStrikeConnectorFactory
    entities/                 records, STIX classes, ids and errors
      models.py               CrowdStrikeIndicator, CrowdStrikeActor,
                              EnrichedCrowdStrikeIndicator (Pydantic)
      stix.py                 CrowdStrikeStix2Indicator (stix2 Indicator subclass),
                              CrowdStrikeIndicatorBundle
      ids.py                  deterministic STIX ids in the CrowdStrike namespace
      errors.py               CrowdStrikeAPIError, IndicatorValidationError,
                              IndicatorConversionError
    extract/                  calls to the CrowdStrike API
      api.py                  FalconPy response checks shared by every call
      extractor.py            CrowdStrikeIndicatorExtractor (FalconPy)
      actors.py               CrowdStrikeActorEnricher (FalconPy)
    transform/                pure conversions to STIX
      transformer.py          CrowdStrikeIndicatorTransformer
      malware.py              CrowdStrikeAddMalware
      attack.py               AttackPatternCatalog, CrowdStrikeAddAttackPatterns
      bundle.py               MakeStixBundle
tests/                        pytest, no network
```

Dependency rule: `shared/` depends only on the standard library, Pydantic,
pydantic-settings and stix2 (loaders take STIX bundles), never on a source. `crowdstrike_indicators/`
depends on `shared/`: inside it, `extract/` and `transform/` both depend on
`entities/`, never on each other, and `factory.py`, which assembles them,
depends on both. The command line, `shared/cli.py`, knows no source: it
imports the factory named by `--factory` when it runs. Runtime
dependencies are `crowdstrike-falconpy`, `pydantic`, `pydantic-settings` and
`stix2`. There is no
pycti and no connectors-sdk.

### The extraction contract

```python
class AbstractExtractor[T: BaseModel](ABC):
    def extract(self, from_date: datetime, max_element_count: int) -> list[tuple[datetime, T]]: ...
```

- Returns items whose datetime is **equal to or later than** `from_date`,
  sorted by ascending datetime, each paired with that datetime.
- Returns at most `max_element_count` items, the earliest ones. An empty list
  means nothing is available.
- To resume, pass the latest returned datetime as the next `from_date`.
- `from_date` must carry a timezone, and `max_element_count` must be 1 or more.

For CrowdStrike, an indicator's datetime is the Unix second at the start of
its `_marker`, the field the API paginates on. Any timezone-aware `from_date`
works, including dates before 2001-09-09 and before 1970: the first cursor is
always written with 10 digits (`0946684800` for 2000-01-01, `0000000000` before
1970), since markers compare as strings.

### The enrichment contract

```python
class AbstractEnricher[T: BaseModel](ABC):
    def extract(self, key: str) -> T | None: ...
    def reset_cache(self) -> None: ...
    def _fetch(self, key: str) -> T | None: ...   # the only method to implement
```

An enricher looks up, by key, an item that an extractor's items only name,
such as an actor named by an indicator.

- `extract(key)` returns the validated item the source holds for `key`, or
  `None` when it holds none. `None` never reports an error: errors are raised.
- Every result is cached under its key, `None` included: a key reaches the
  source at most once until the cache is reset.
- A lookup that raises caches nothing, so the next lookup of that key tries
  the source again.
- `reset_cache()` empties the cache. The caller decides how long a cache
  lives; an extractor using an enricher typically resets it at the start of
  each extraction.

### The transformation contract

```python
class AbstractTransformer[InputType, OutputType](ABC):
    def convert(self, item: InputType) -> OutputType: ...
```

- One input item gives one output value. A transformer that turns one item
  into several objects declares a collection, such as `list[...]`, as its
  `OutputType`.
- Both types are unconstrained, so transformers can follow an extractor and
  follow one another: two transformers chain when the first one's
  `OutputType` is the second one's `InputType`. stix2 objects are not Pydantic
  models, which is why `InputType` has no `BaseModel` bound.
- An item that cannot be converted raises an error naming it. No empty or
  placeholder value is returned.
- The item is left unchanged.

### The loading contract

```python
class AbstractLoader(ABC):
    def load(self, bundle: stix2.v21.Bundle) -> None: ...
```

- A loader takes one standard STIX 2.1 bundle, the output of `MakeStixBundle`,
  and returns nothing. A normal return means the whole bundle has been
  delivered.
- A bundle that cannot be delivered raises an error.
- The bundle is left unchanged.

`RecordToFile(directory)` is the first loader: it writes each bundle to
`<directory>/<bundle id>.json`, as indented STIX JSON.

```python
from pathlib import Path
from shared.record_to_file import RecordToFile

loader = RecordToFile(Path("bundles"))
loader.load(stix_bundle)   # -> bundles/bundle--fe24cab3-d021-56f9-af58-867c5a0cdb23.json
```

- The directory is created when missing; building the loader creates nothing.
- The same bundle always gives the same bytes. Bundle ids are deterministic,
  so loading the same indicator again replaces its file with an identical one.
- The file is written to a hidden temporary file, then renamed into place:
  a reader never sees half a bundle, and a failure (full disk, missing
  permission, a path that is a file) is raised, with the previous file, if
  any, left as it was.
- `stix2.parse(path.read_text(), allow_custom=True)` reads a bundle back.

The command line does not run a loader yet.

### The connector

`Connector` assembles an extractor, a chain of transformers and a loader, and
runs them on a schedule. It knows nothing of CrowdStrike.

```
   +------------------ wait run_frequency (unless draining) ------------------+
   v                                                                          |
extract(cursor, max) -> [(dt, item)] -> t1 -> t2 -> ... -> tn -> loader.load  |
   |                                                                          |
   +--> cursor = latest dt extracted  -----------------------------------------+
```

```python
from datetime import UTC, datetime, timedelta
from pathlib import Path

from crowdstrike_indicators.factory import CrowdStrikeConnectorFactory
from shared.connector import Connector
from shared.record_to_file import RecordToFile

factory = CrowdStrikeConnectorFactory()  # CROWDSTRIKE_* from the environment or ./.env
connector = Connector(
    factory.create_extractor(),
    factory.create_transformers(),
    RecordToFile(Path("bundles")),
)
connector.run(datetime(2026, 11, 1, tzinfo=UTC), timedelta(minutes=30), 10_000)
```

- **The chain is checked at construction.** The extractor's item type must be
  the first transformer's input type, each output type the next input type,
  and the last output type `stix2.v21.Bundle`, the loader's input. A
  mismatch raises a `TypeError` naming both types, for example
  `transformer 1 (CrowdStrikeAddMalware) expects CrowdStrikeStix2Indicator but
  extractor (CrowdStrikeIndicatorExtractor) produces
  EnrichedCrowdStrikeIndicator`.
  A component that does not declare its type arguments is rejected too.
- **`run_once(from_date, max_element_count)`** runs one cycle and returns a
  `CycleResult(extracted, loaded, skipped, next_from_date)`. The next
  `from_date` is the latest extracted datetime, or `from_date` when nothing
  was extracted.
- **`run(from_date, run_frequency, max_element_count)`** repeats cycles
  forever from the returned `from_date`. After a full batch that moved the
  cursor it starts again at once, to drain a backlog; otherwise it waits
  `run_frequency` after the cycle ends. A full batch that does not move the
  cursor (one second holding `max_element_count` items) logs a warning and
  waits rather than looping. A non-positive `run_frequency`, a naive
  `from_date` or a `max_element_count` below 1 are rejected before any
  extraction.
- **Errors.** An item whose transformation fails is logged and skipped; the
  others go through and the cursor still moves past it. An extraction or
  loading failure aborts the cycle without moving the cursor; `run` logs it,
  waits `run_frequency` and retries from the same `from_date`. Ctrl+C stops
  the connector.
- The cursor lives in memory: a restarted process starts from the `from_date`
  it is given. The waiting function can be injected (`sleep=`), which the
  tests use to stop the endless loop.

### The factory contract

A factory turns one validated configuration into a source's extractor and
chain of transformers, so that every caller gets the same components from the
same settings.

```python
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from shared.factory import AbstractConnectorFactory, ConnectorConfigurationError


class MySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MYSOURCE_", extra="ignore")

    api_key: SecretStr
    base_url: str = "https://api.example.com"


class MyFactory(AbstractConnectorFactory[MySettings]):
    def create_extractor(self):
        ...  # build the extractor from self.settings

    def create_transformers(self):
        ...  # build the chain of transformers from self.settings


try:
    MyFactory()  # reads MYSOURCE_* from the environment, then from ./.env
except ConnectorConfigurationError as error:
    print(error)  # invalid configuration:
    #                 MYSOURCE_API_KEY: missing

factory = MyFactory(api_key="key")  # given values win over the environment
print(factory.settings.base_url)  # https://api.example.com
```

- **The settings model is the type argument.** The contract reads it from
  `AbstractConnectorFactory[MySettings]`; it must be a pydantic-settings
  `BaseSettings` model.
- **Settings are loaded at construction**, in decreasing precedence: values
  given to the factory, the process environment, then the `.env` file,
  `./.env` unless `env_file=` names another one (`None` for none). A missing
  file is not an error.
- **Settings are validated in full at construction.** Any missing or invalid
  parameter raises one `ConnectorConfigurationError` (a `ValueError`) whose
  `problems` name every parameter at fault by its environment variable, with
  the reason, and never the rejected value. A factory that was built holds a
  complete, valid configuration: nothing is validated later.
- **`create_extractor()` and `create_transformers()`** build the components
  from the settings, without contacting the source.
- **The factory builds neither the loader nor the connector.** The caller
  chooses the destination and assembles the `Connector`, which checks the
  chain:

```python
connector = Connector(
    factory.create_extractor(), factory.create_transformers(), loader
)
```

### Shared errors

`shared/errors.py` holds three errors any source can raise. They are a
toolkit: the contracts above require an error that says what failed, not one
of these types, and the connector and the command line handle them like any
other error.

| Error | Carries | Message |
| --- | --- | --- |
| `SourceAPIError` | `source`, `status_code`, `message` | `<source> API error <status>: <message>` |
| `ItemValidationError` | `item_id` (or `None`), `errors` (JSON-safe), `raw` | `Item <id> failed validation (<n> error(s)): <field>: <message>; ...` |
| `ItemConversionError` | `item_id`, `reason` | `Item <id> could not be converted: <reason>` |

`ItemValidationError.from_validation_error` builds the validation error from
a Pydantic `ValidationError`, chained as its cause. The caller says which
field identifies a record:

```python
try:
    return Model.model_validate(raw)
except ValidationError as error:
    raise ItemValidationError.from_validation_error(
        error, raw, item_id=raw.get("id")
    ) from error
```

The meaning of a status code is left to the source: CrowdStrike uses `0` for
a response without an integer status code.

### The CrowdStrike factory

`CrowdStrikeConnectorFactory` implements the factory contract for this source,
with `CrowdStrikeSettings` as its settings (see [Setup](#setup) for the keys).

- **Settings.** `CROWDSTRIKE_CLIENT_ID` and `CROWDSTRIKE_CLIENT_SECRET` are
  required (both `SecretStr`, never displayed), `CROWDSTRIKE_BASE_URL` defaults
  to `https://api.crowdstrike.com`, `CROWDSTRIKE_ATTACK_DATA` is the optional
  path of a local ATT&CK dataset, which must exist. Empty values count as
  unset, and keys that are not settings are ignored, so a `.env` shared with
  other tools works.
- **The ATT&CK dataset is read at construction**, once per factory: a file
  that is not a STIX bundle fails construction, naming the file, like a
  missing credential.
- **`create_extractor()`** returns a new `CrowdStrikeIndicatorExtractor` with
  a new `CrowdStrikeActorEnricher` (and so an empty actor cache). Every
  extractor and enricher of a factory shares one FalconPy `Intel` client,
  built on the first API call only: FalconPy authenticates when the client is
  built, and creating components must not contact CrowdStrike.
- **`create_transformers()`** returns new `CrowdStrikeIndicatorTransformer`,
  `CrowdStrikeAddMalware`, `CrowdStrikeAddAttackPatterns` when a dataset is
  set, and `MakeStixBundle`.

### CrowdStrike actors

An indicator names its actors by a token such as `SALTYSPIDER`. The extractor
looks each one up with `CrowdStrikeActorEnricher` and returns
`EnrichedCrowdStrikeIndicator` items: a `CrowdStrikeIndicator`, unchanged,
plus `actor_objects_list`, the `CrowdStrikeActor` records its `actors`
resolve to.

- **One request per name.** The enricher calls `QueryIntelActorEntities`
  (`GET /intel/combined/actors/v1`) with the filter `name:'<token>'` and the
  explicit field list `id`, `name`, `slug`, `url`, `known_as`, `description`,
  `short_description`, `first_activity_date`, `last_activity_date`,
  `motivations`, `objectives` and `actor_type`: what the existing connector
  packs into its Intrusion Sets, plus `slug`. The API does not honor this
  list: on real data it returns 10 more fields (`active`, `capabilities`,
  `created_date`, `last_modified_date`, `notify_users`, `origins`, `status`,
  `target_countries`, `target_industries`, `target_regions`), which are kept
  as undeclared fields.
- **Matching.** A returned actor matches when its `name` or `slug`,
  uppercased without spaces and hyphens, equals the token: `SALTY SPIDER`
  and `salty-spider` both match `SALTYSPIDER`. The first match wins; with
  none, the name is unresolved. Unlike the existing connector, there is no
  fallback to another actor of the response. Checked on the real API with
  the indicators of November 2026: every name they carry (`SALTYSPIDER`,
  `WIZARDSPIDER`, `CHARMINGKITTEN`, `MYTHICLEOPARD`, `QUILTEDTIGER`) resolves.
- **Cache.** Each name, resolved or not, is looked up at most once per
  extraction: the extractor empties the enricher's cache when an extraction
  starts. A month of real data names 6 distinct actors on 445 of 178,695
  indicators.
- **Only for returned indicators.** Actors are looked up after the cut to
  `max_element_count`, and not at all when the extraction fails.
- **A missing actor never fails the extraction.** A name that resolves to
  nothing, or whose lookup fails (an API error such as a 403 when the actors
  scope is missing, a network error), is logged and left out of
  `actor_objects_list`. A failed lookup is not cached, so the next indicator
  naming that actor tries again. One summary line per extraction counts the
  names looked up, resolved, unresolved and failed, at warning level when
  any lookup failed.
- `actor_objects_list` follows the order of `actors`, holds each actor once
  (by `id`), and is `[]` when the indicator names no actor or none resolves.
- `CrowdStrikeActor` is as lenient as the indicator model: it requires `id`
  and `name`, keeps undeclared fields as received (`known_as`, `motivations`
  and `objectives` are left undeclared until their shape is confirmed), and
  an actor that fails validation is logged and skipped.

### CrowdStrike indicators as STIX

`CrowdStrikeIndicatorTransformer` converts an `EnrichedCrowdStrikeIndicator` into a
`CrowdStrikeStix2Indicator`: a stix2 `Indicator` (STIX 2.1) that declares extra
`x_crowdstrike_*` properties. Two rules apply:

- **Native STIX is filled where the meaning matches** (table below).
- **Nothing is lost, nothing is repeated.** A CrowdStrike field goes into an
  `x_crowdstrike_*` property only when no native property holds it:

| Fields | Where they live |
|---|---|
| `id`, `indicator`, `type`, `last_updated`, `published_date`, `deleted` | only in native properties (see the table below); `type` is read back from the pattern's object path |
| `malicious_confidence` | `confidence`; also `x_crowdstrike_malicious_confidence` when `confidence` cannot be set (`unverified`, an unknown value) |
| `kill_chains` | `kill_chain_phases`; also `x_crowdstrike_kill_chains`, with the whole list, when a value has no phase |
| `_marker`, `labels` (with their dates), `actors`, `malware_families`, `targets`, `vulnerabilities`, `threat_types`, `domain_types`, `ip_address_types` | `x_crowdstrike_<field>`, named after the API field without its leading underscore (`_marker` becomes `x_crowdstrike_marker`) |
| `actor_objects_list` | `x_crowdstrike_actor_objects_list`, each actor as the actors API returned it, undeclared fields included; never in `x_crowdstrike_extra` |
| fields the model does not declare (`reports`, `relations`, `scope`, ...) | together in `x_crowdstrike_extra` |

Native properties:

| STIX property | From |
|---|---|
| `pattern` (`pattern_type` `stix`) | `type` and `indicator`, built with stix2's pattern classes, which quote and escape |
| `name` | `indicator` |
| `valid_from`, `created` | `published_date`, or `last_updated` when absent |
| `modified` | `last_updated` |
| `revoked` | `true` when `deleted` is true, absent otherwise |
| `confidence` | `malicious_confidence` on the STIX 2.1 None/Low/Med/High scale: `high` 85, `medium` 50, `low` 15; `unverified` leaves it absent |
| `kill_chain_phases` | `kill_chains`, on `lockheed-martin-cyber-kill-chain`: `C2` becomes `command-and-control`, `ActionOnObjectives` becomes `action-on-objectives`, the 5 others are lowercased; unknown values are skipped |
| `labels` | label names, verbatim and in order |
| `external_references` | `source_name` `CrowdStrike`, `external_id` the CrowdStrike `id` |

Supported types: `domain`, `url`, `ip_address` (IPv4 and IPv6), `hash_md5`,
`hash_sha1` and `hash_sha256`. Any other type raises `ItemConversionError`,
and so does a `published_date` later than `last_updated`.

The STIX `id` is derived from the CrowdStrike id alone: `indicator--` followed
by a UUIDv5 of the CrowdStrike `id` in the namespace
`uuid5(NAMESPACE_DNS, "crowdstrike.com")`. The same CrowdStrike indicator always
gets the same id, with no OpenCTI convention involved. These ids differ from
the ones the existing connector gives in OpenCTI (pycti's, derived from the
pattern): converting them is the job of a later, OpenCTI-specific stage, which
finds the CrowdStrike id in `external_references`.

`stix2.parse` rebuilds a plain `Indicator`, which accepts the
`x_crowdstrike_*` properties only with `allow_custom=True`.

### Malware

`CrowdStrikeAddMalware` is the second step of the chain: it takes the
`CrowdStrikeStix2Indicator` the first step produces and returns a
`CrowdStrikeIndicatorBundle`, an immutable dataclass:

```python
@dataclass(frozen=True)
class CrowdStrikeIndicatorBundle:
    indicator: CrowdStrikeStix2Indicator   # passed through unchanged
    malware: list[Malware]
    attack_patterns: list[AttackPattern]   # left empty by this step
    relationships: list[Relationship]      # every indicates relationship
```

```
CrowdStrikeIndicator --> CrowdStrikeStix2Indicator --> Bundle --> Bundle --> stix2 Bundle
       CrowdStrikeIndicatorTransformer    CrowdStrikeAddMalware  |      MakeStixBundle
                                                CrowdStrikeAddAttackPatterns
                                                (only with an ATT&CK dataset)
```

- One STIX 2.1 Malware per distinct name of `x_crowdstrike_malware_families`,
  in source order: `name` unchanged (no CamelCase splitting), `is_family` true.
- One `indicates` relationship from the indicator to each Malware.
- The indicator is passed through as is, so the family names also stay in its
  `x_crowdstrike_malware_families`. Each step only adds objects.
- An indicator naming no family gives empty lists.

Ids and dates depend on the input only, so the same input always gives the
same output:

| Object | `id` | `created`, `modified` |
|---|---|---|
| Malware | `malware--` + UUIDv5 of `malware:<name>` in the CrowdStrike namespace | the Unix epoch, `1970-01-01T00:00:00.000Z`: CrowdStrike gives no date for a family |
| `indicates` relationship | `relationship--` + UUIDv5 of `indicates:<indicator id>:<malware id>` | the indicator's |

Every copy of a Malware is therefore identical, id and content, whichever
indicator names it, so a later stage can deduplicate them by id. The existing
connector uses pycti ids and the clock time instead; converting to OpenCTI ids
and dates belongs to the OpenCTI stage.

### Attack patterns

`CrowdStrikeAddAttackPatterns` is the third step: it takes a bundle and returns
it with MITRE ATT&CK AttackPatterns added. It is constructed with an
`AttackPatternCatalog`, loaded once from a local copy of the MITRE ATT&CK
Enterprise STIX dataset. Nothing is downloaded: get the file from the
[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
repository, for example `enterprise-attack/enterprise-attack-17.1.json`, the
version the existing connector uses by default.

```python
catalog = AttackPatternCatalog.from_file(Path("enterprise-attack-17.1.json"))
bundle = CrowdStrikeAddAttackPatterns(catalog).convert(bundle)
```

Each label `MitreATTCK/<tactic>/<technique>` of the indicator is resolved by
the catalog:

1. only live techniques count: revoked and deprecated AttackPatterns are left
   out;
2. the technique name matches on letters and digits, case-insensitively:
   `PowerShell` finds `PowerShell` (T1059.001), and
   `RegistryRunKeysStartupFolder` finds `Registry Run Keys / Startup Folder`
   (T1547.001);
3. when several techniques share the name, the tactic chooses:
   `CommandAndControl/Steganography` is T1001.002, while
   `DefenseEvasion/Steganography` is T1027.003;
4. a single remaining technique is the result; none, or several, resolve to
   nothing.

For every distinct technique found, in label order, the step adds a light
copy of MITRE's AttackPattern and an `indicates` relationship from the
indicator, with the same id rule and dates as the Malware relationships.
Objects already in the bundle are kept.

The light copy keeps what identifies the technique, and nothing else:

```json
{
  "type": "attack-pattern",
  "spec_version": "2.1",
  "id": "attack-pattern--3c4a2599-71ee-4405-ba1e-0e28414b4bc5",
  "created": "2017-05-31T21:30:20.537Z",
  "modified": "2025-04-15T19:58:24.318Z",
  "name": "Data from Local System",
  "external_references": [
    {"source_name": "mitre-attack", "url": "https://attack.mitre.org/techniques/T1005", "external_id": "T1005"}
  ]
}
```

- MITRE's `id` and dates are kept, so the indicator `indicates` MITRE's own
  technique, and a later stage can match it by id or T-id.
- Left out: `description`, `kill_chain_phases`, every `x_mitre_*` property, the
  other external references (citations), and `created_by_ref` and
  `object_marking_refs`: they point to MITRE's identity and marking, which are
  not in the bundle, and OpenCTI rejects references to objects a bundle does not
  contain. The tactic stays readable in the CrowdStrike label on the indicator.
- Each technique is copied once per step and shared by every bundle.

A label that resolves to nothing adds nothing and stays on the indicator. With
ATT&CK 17.1, over a month of real data, 86 of the 106 distinct CrowdStrike
ATT&CK labels resolve. 15 name techniques ATT&CK has renamed or retired (such as
`RemoteFileCopy`, now `Ingress Tool Transfer`), and 5 stay ambiguous within
their tactic (`ResourceDevelopment/Botnet`, `Malware`, `Server`, `Domains`,
`WebServices`). The existing connector resolves 75, plus the 5 ambiguous ones
picked arbitrarily.

`tests/fixtures/attack_extract.json` holds AttackPatterns copied unchanged
from MITRE ATT&CK Enterprise 17.1, © The MITRE Corporation, reproduced under
the [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

### STIX bundle

`MakeStixBundle` is the last step: it turns a `CrowdStrikeIndicatorBundle`
into a standard STIX 2.1 bundle (`stix2.v21.Bundle`), the form a STIX consumer
such as OpenCTI takes.

```json
{
  "type": "bundle",
  "id": "bundle--fe24cab3-d021-56f9-af58-867c5a0cdb23",
  "objects": [
    {"type": "indicator", "...": "..."},
    {"type": "malware", "...": "..."},
    {"type": "attack-pattern", "...": "..."},
    {"type": "relationship", "...": "..."}
  ]
}
```

- `objects` holds the indicator, then the Malware objects, the AttackPatterns
  and the relationships, unchanged, `x_crowdstrike_*` properties included.
  Read it back with `stix2.parse(..., allow_custom=True)`.
- The `id` is `bundle--` followed by the UUIDv5 of `bundle:<indicator id>` in
  the CrowdStrike namespace: the same input always gives the same bundle.
- Every reference must resolve inside the bundle: a `*_ref` or `*_refs` value
  naming an object the bundle does not hold makes the step raise
  `ItemConversionError`, naming the indicator and the missing id. OpenCTI
  rejects such bundles, so the gap is caught here.

## Setup

Python 3.12 or later. The project is declared in `pyproject.toml`, which
installs the command line as the `connector-cli` command.

With [uv](https://docs.astral.sh/uv/), there is nothing to install by hand:
the first `uv run` creates `.venv` in this folder and installs the project
and its dependencies in it.

```sh
cd external-import/crowdstrike-indicators-poc
cp .env.example .env                           # then fill in the credentials
uv run connector-cli --help
```

Or with pip, in a virtual environment of your own:

```sh
cd external-import/crowdstrike-indicators-poc
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'                       # runtime + pytest
cp .env.example .env                           # then fill in the credentials
connector-cli --help
```

The install is editable: changes under `src/` apply without reinstalling.
`uv run` writes a `uv.lock`, which is git-ignored.

`.env` keys (a variable set in the environment wins over the file):

| Key | Required | Default |
|---|---|---|
| `CROWDSTRIKE_CLIENT_ID` | yes | |
| `CROWDSTRIKE_CLIENT_SECRET` | yes | |
| `CROWDSTRIKE_BASE_URL` | no | `https://api.crowdstrike.com` (US-1). Other regions: `https://api.us-2.crowdstrike.com`, `https://api.eu-1.crowdstrike.com`, ... |
| `CROWDSTRIKE_ATTACK_DATA` | no | none. Path of a local MITRE ATT&CK Enterprise STIX bundle; when set, the chain adds the AttackPatterns (see [Attack patterns](#attack-patterns)). |

Both subcommands read this configuration through the
[CrowdStrike factory](#the-crowdstrike-factory) and stop with status 2, naming
every missing or invalid key, before doing anything. An empty value counts as
unset. Keys that are not in this table are ignored. A `${NAME}` reference in a
value, quoted or not, is replaced by the value of `NAME`; a value that must
hold `${` literally goes in the process environment instead.

The API client needs the **Indicators (Falcon Intelligence): Read** scope, and
the **Actors (Falcon Intelligence): Read** scope to resolve actors. Without
the actors scope, `extract` still succeeds, with every `actor_objects_list`
empty and the failures in the logs.
`.env` is git-ignored. Never commit it.

## Usage

`connector-cli` runs the components of any source that has a
[connector factory](#the-factory-contract), named by
`--factory MODULE:CLASS`. It is a debug tool: it prints what the components
return, as JSON, without reshaping it. Run it from this folder with
`uv run connector-cli`, or with `connector-cli` alone in an activated virtual
environment where the project is installed. For CrowdStrike, a shell alias
saves typing the factory each time:

```sh
alias cs-cli='uv run connector-cli --factory crowdstrike_indicators.factory:CrowdStrikeConnectorFactory'
```

The examples below use that alias. The command has two subcommands:

- `extract` runs the factory's extractor (for CrowdStrike, it calls the API);
- `transform` runs one item through the factory's chain of transformers.

The configuration comes from the environment, then from `./.env` or the file
given by `--env-file`, never from arguments. The factory validates all of it
before anything runs, so `transform` needs a complete configuration too even
though it never contacts CrowdStrike: placeholder credentials are enough.

| Option, before the subcommand | |
|---|---|
| `--factory MODULE:CLASS` | required. The connector factory, for example `crowdstrike_indicators.factory:CrowdStrikeConnectorFactory`. |
| `--env-file PATH` | configuration file, read after the environment; `./.env` by default. |
| `--log-level LEVEL` | `DEBUG`, `INFO` (default), `WARNING` or `ERROR`. At `DEBUG`, a failure also logs its full traceback. |

### `extract`

```sh
# The 50 earliest indicators from 1 November 2026 (UTC) onwards
cs-cli extract --from 2026-11-01T00:00:00Z --max 50

# Same, written to a file instead of standard output, to read it later
cs-cli extract --from 2026-11-01 --max 50 --output raw-dumps/2026-11-01.json

# Credentials from another file, with debug logs
uv run connector-cli --factory crowdstrike_indicators.factory:CrowdStrikeConnectorFactory \
    --env-file ~/secrets/crowdstrike.env --log-level DEBUG \
    extract --from 2026-11-01 --max 10
```

| Option | |
|---|---|
| `--from DATETIME` | required. ISO 8601. Without a timezone, it is read as UTC. |
| `--max N` | required. Maximum number of items, 1 or more. |
| `--output FILE` | write the result, the same JSON array as on standard output, to `FILE` instead, only when the extraction succeeds. Missing parent directories are created and an existing file is replaced. `raw-dumps/` and `*.raw.json` are git-ignored. |

Standard output holds a single JSON array, one object per pair the extractor
returns, so it can be piped (`| jq ...`). Logs and errors go to standard
error. For CrowdStrike, each `item` is an indicator with its API field names:

```json
[
  {
    "datetime": "2026-11-01T00:00:03+00:00",
    "item": {
      "id": "domain_evil.example",
      "indicator": "evil.example",
      "type": "domain",
      "_marker": "1793491203a1b2c3",
      "last_updated": "2026-11-01T00:00:03Z",
      "actors": ["SALTYSPIDER"],
      "...": "every other field of the model, and every undeclared field returned by the API",
      "actor_objects_list": [
        {"id": 123, "name": "SALTY SPIDER", "slug": "salty-spider", "...": "every other actor field"}
      ]
    }
  }
]
```

The item holds every field of the model, including those the API did not
return (at their default, `null` or `[]`). Fields the model does not declare
yet (`reports`, `relations`, ...) are printed as received. Every indicator
holds `actor_objects_list`, `[]` when it names no actor or none resolves.

### `transform`

`transform` reads **one** JSON value, from a file or from standard input, and
validates it as the input of the chain's first transformer. For CrowdStrike,
that is one indicator in the API shape: one element of an API page's
`resources`, such as a row of `tests/fixtures/indicators_sample.json`, or the
`item` of one element of the `extract` output, with its `actor_objects_list`
(`jq '.[0].item'`). It then runs the chain, each step taking the previous
output. The CrowdStrike chain is:

1. `CrowdStrikeIndicatorTransformer`: the STIX 2.1 indicator;
2. `CrowdStrikeAddMalware`: the bundle of that indicator, its Malware objects
   and its `indicates` relationships;
3. with a dataset only, set by `CROWDSTRIKE_ATTACK_DATA`,
   `CrowdStrikeAddAttackPatterns`: the same bundle with the MITRE ATT&CK
   AttackPatterns its labels name, resolved against that local ATT&CK dataset
   (see [Attack patterns](#attack-patterns));
4. always last, `MakeStixBundle`: the standard STIX 2.1 bundle of all those
   objects, ready for a STIX consumer (see [STIX bundle](#stix-bundle)).

It is the chain `CrowdStrikeConnectorFactory.create_transformers()` returns,
so what `transform` shows is what a connector built from the same
configuration runs. `transform` never looks actors up: it keeps the
`actor_objects_list` it is given, and an indicator without one converts as
having no resolved actor.

```sh
# transform never contacts CrowdStrike: placeholder credentials are enough
export CROWDSTRIKE_CLIENT_ID=FAKE_CLIENT_ID CROWDSTRIKE_CLIENT_SECRET=FAKE_CLIENT_SECRET

# Take a domain row of the committed sample as input
uv run python -c "import json; rows = json.load(open('tests/fixtures/indicators_sample.json'))['resources']; print(json.dumps(next(r for r in rows if r['type'] == 'domain')))" > indicator.json

# From a file
cs-cli transform indicator.json

# From standard input
cs-cli transform < indicator.json

# With attack patterns: a row with ATT&CK labels, and a local ATT&CK dataset
# (the test extract here, or a downloaded enterprise-attack-17.1.json)
uv run python -c "import json; print(json.dumps(json.load(open('tests/fixtures/indicators_sample.json'))['resources'][0]))" > indicator-attack.json
CROWDSTRIKE_ATTACK_DATA=tests/fixtures/attack_extract.json cs-cli transform indicator-attack.json
```

Without a dataset, the attack pattern step is skipped and the bundle's
`attack_patterns` is empty. A missing or invalid dataset file exits with status
2 before any step runs; the dataset is never downloaded.

Each step is printed as soon as it finishes: a `Step N - TYPE` line, the
step's output as indented JSON, then an empty line. If a step fails, the steps
before it stay on standard output and the error goes to standard error.

```
Step 1 - CrowdStrikeIndicatorTransformer
{
  "type": "indicator",
  "id": "indicator--f975582d-ec64-5f6c-ac8c-1fdea0f69e0b",
  "name": "malicious-7.example",
  "pattern": "[domain-name:value = 'malicious-7.example']",
  "...": "...",
  "x_crowdstrike_malware_families": ["ExampleFamily4", "ExampleFamily6", "ExampleFamily7"]
}

Step 2 - CrowdStrikeAddMalware
{
  "indicator": {"...": "the indicator of step 1, unchanged"},
  "malware": [
    {"type": "malware", "id": "malware--06d31b08-d590-5298-8440-23b86775f679", "name": "ExampleFamily4", "is_family": true, "...": "..."}
  ],
  "attack_patterns": [],
  "relationships": [
    {"type": "relationship", "relationship_type": "indicates", "source_ref": "indicator--f975582d-...", "target_ref": "malware--06d31b08-...", "...": "..."}
  ]
}

Step 3 - MakeStixBundle
{
  "type": "bundle",
  "id": "bundle--fe24cab3-d021-56f9-af58-867c5a0cdb23",
  "objects": [{"type": "indicator", "...": "..."}, {"type": "malware", "...": "..."}, {"type": "relationship", "...": "..."}]
}
```

### How values are printed

Values JSON cannot write directly are converted, nested ones included:

| Value | Printed as |
|---|---|
| STIX object (stix2, custom ones included) | its STIX JSON: STIX timestamps (`2015-01-30T14:05:48.000Z`), STIX property order, then the `x_crowdstrike_*` properties |
| Pydantic model | every field, under its alias (`_marker`, not `marker`) |
| dataclass (`CrowdStrikeIndicatorBundle`) | an object of its fields, in declaration order |
| date, datetime | ISO 8601 |

Any other type is an error (status 1) naming it, and its step gets no header.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success, including an empty result (`[]`) for `extract` |
| 1 | a component failed or the input could not be read: `error: <message>` on standard error, with the full traceback at `--log-level DEBUG`. For CrowdStrike: an API error (its status and message), an indicator that does not match the model (its `id` and each failing field), an indicator that cannot be converted (unsupported type, `published_date` after `last_updated`). For `transform`: input that is not valid JSON, or that fails validation |
| 2 | usage or configuration error: missing or unusable `--factory`, no or unknown subcommand, bad argument, missing or invalid configuration key (every one is named, for `transform` too), missing `--env-file`, missing `transform` input file, missing or invalid ATT&CK dataset (`CROWDSTRIKE_ATTACK_DATA`) |

## Tests

```sh
uv run --extra test pytest                      # from this folder
# or as CI does, from the repository root:
bash run_test.sh external-import/crowdstrike-indicators-poc/tests/test-requirements.txt
```

## Known limitations

- **Overlap when resuming.** Datetimes have one-second precision, and
  `from_date` is included. Resuming from the latest returned datetime returns
  every indicator of that second again. This is harmless downstream, because
  the same indicator gets the same ID. If one second holds more indicators
  than `--max`, resuming returns the same rows every time and never moves
  forward. Keep `--max` well above the largest same-second burst: a month of
  real data peaked at 445 indicators in one second, so a `--max` above 10000
  always moves forward.
- **The model is inferred, not verified.** Fields come from FalconPy's filter
  documentation and from the existing CrowdStrike connector. It is
  deliberately lenient. The `extract` output keeps every field the API sent,
  undeclared ones included, so it shows the real shape.
- **One invalid indicator stops the run**, with nothing printed on standard
  output. This is on purpose while the model is being refined.
- **The actor matching rule is checked on five names only.** Those of
  November 2026 all resolve. A name whose actor's `name` and `slug` both
  differ from the token by more than spaces, hyphens and case would stay
  unresolved, which only the summary log line shows.
- **A missing actors scope only shows in the logs.** The extraction succeeds
  with empty actor lists. Failed lookups are not cached, so each indicator
  naming an actor costs one failing request (about 445 a month on real data).
- **Actors are copied onto each indicator** that names them: on real data,
  `SALTY SPIDER` appears on about 418 indicators a month. Since the API
  ignores the requested field list, each copy holds all 22 fields it returns.
- **No state, no OpenCTI.** Every run is independent. `extract` prints the raw
  API data, and `transform` converts one indicator at a time.
- **A few distinctions do not survive the conversion.** stix2 drops empty
  lists, so an empty CrowdStrike list gives no `x_crowdstrike_*` property and
  reads back as absent. A missing `published_date` reads back as equal to
  `last_updated` (`created` falls back to it), a missing `deleted` as `false`,
  and `malicious_confidence` in lowercase (`HIGH` and `high` both give 85). Real
  data always has these fields, in lowercase, so no value is lost.
