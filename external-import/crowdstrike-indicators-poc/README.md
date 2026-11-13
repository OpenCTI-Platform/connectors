# CrowdStrike indicators: proof of concept

> **Status: proof of concept, command line only.** Not a connector: it does
> not talk to OpenCTI and keeps no state between runs.

This folder tests a new organization for connectors, built from small
contracts that do not depend on OpenCTI:

1. an extractor: typed, validated CrowdStrike Falcon Intelligence indicators,
   run from the command line against the real API, so the indicator model can
   be refined from actual data;
2. transformers, chained:
   - each indicator converted into one STIX 2.1 indicator that loses nothing
     of the source data;
   - that indicator bundled with one Malware per family it names, and the
     `indicates` relationships linking them;
   - the MITRE ATT&CK AttackPatterns its labels name added to the bundle, with
     their `indicates` relationships, from a local ATT&CK dataset.

## Layout

```
src/
  shared/                     contracts, independent of any source
    extractor.py              AbstractExtractor[T: BaseModel]
    transformer.py            AbstractTransformer[InputType, OutputType]
  crowdstrike_indicators/     CrowdStrike implementation
    models.py                 CrowdStrikeIndicator (Pydantic)
    extractor.py              CrowdStrikeIndicatorExtractor (FalconPy)
    stix.py                   CrowdStrikeStix2Indicator (stix2 Indicator subclass),
                              CrowdStrikeIndicatorBundle
    ids.py                    deterministic STIX ids in the CrowdStrike namespace
    transformer.py            CrowdStrikeIndicatorTransformer
    malware.py                CrowdStrikeAddMalware
    attack.py                 AttackPatternCatalog, CrowdStrikeAddAttackPatterns
    errors.py                 CrowdStrikeAPIError, IndicatorValidationError,
                              IndicatorConversionError
    dotenv.py                 minimal .env reader
    cli.py, __main__.py       command line
tests/                        pytest, no network
```

Dependency rule: `shared/` depends only on the standard library and Pydantic,
never on a source. `crowdstrike_indicators/` depends on `shared/`. Runtime
dependencies are `crowdstrike-falconpy`, `pydantic` and `stix2`. There is no
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
its `_marker`, the field the API paginates on.

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

### CrowdStrike indicators as STIX

`CrowdStrikeIndicatorTransformer` converts a `CrowdStrikeIndicator` into a
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
`hash_sha1` and `hash_sha256`. Any other type raises `IndicatorConversionError`,
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
CrowdStrikeIndicator --> CrowdStrikeStix2Indicator --> Bundle --> Bundle
       CrowdStrikeIndicatorTransformer    CrowdStrikeAddMalware  CrowdStrikeAddAttackPatterns
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

For every distinct technique found, in label order, the step adds MITRE's
AttackPattern object as is (MITRE's id, name, T-id, tactics and dates) and an
`indicates` relationship from the indicator, with the same id rule and dates as
the Malware relationships. Objects already in the bundle are kept.

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

## Setup

Python 3.12 or later.

```sh
cd external-import/crowdstrike-indicators-poc
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r tests/test-requirements.txt     # runtime + pytest
cp .env.example .env                           # then fill in the credentials
```

`.env` keys (a variable set in the environment wins over the file):

| Key | Required | Default |
|---|---|---|
| `CROWDSTRIKE_CLIENT_ID` | yes | |
| `CROWDSTRIKE_CLIENT_SECRET` | yes | |
| `CROWDSTRIKE_BASE_URL` | no | `https://api.crowdstrike.com` (US-1). Other regions: `https://api.us-2.crowdstrike.com`, `https://api.eu-1.crowdstrike.com`, ... |

The API client needs the **Indicators (Falcon Intelligence): Read** scope.
`.env` is git-ignored. Never commit it.

## Usage

Run from this folder, with `src` on the Python path. The command has two
subcommands:

- `extract` calls the CrowdStrike API and prints the indicators;
- `transform` converts one indicator into STIX, without credentials or network.

### `extract`

```sh
# The 50 earliest indicators from 1 November 2026 (UTC) onwards
PYTHONPATH=src python -m crowdstrike_indicators extract --from 2026-11-01T00:00:00Z --max 50

# Same, and also save the raw API pages, to study the real response shape
PYTHONPATH=src python -m crowdstrike_indicators extract --from 2026-11-01 --max 50 \
    --dump-raw raw-dumps/first.raw.json

# Credentials from another file, with debug logs
PYTHONPATH=src python -m crowdstrike_indicators extract --from 2026-11-01 --max 10 \
    --env-file ~/secrets/crowdstrike.env --log-level DEBUG
```

| Option | |
|---|---|
| `--from DATETIME` | required. ISO 8601. Without a timezone, it is read as UTC. |
| `--max N` | required. Maximum number of indicators, 1 or more. |
| `--env-file PATH` | credentials file, `./.env` by default. |
| `--dump-raw PATH` | also write every raw API page received, as a JSON array, even when the extraction fails. `raw-dumps/` and `*.raw.json` are git-ignored. |
| `--log-level LEVEL` | `DEBUG`, `INFO` (default), `WARNING` or `ERROR`. |

Standard output holds a single JSON array, so it can be piped (`| jq ...`).
Logs and errors go to standard error.

```json
[
  {
    "datetime": "2026-11-01T00:00:03+00:00",
    "indicator": {
      "id": "domain_evil.example",
      "indicator": "evil.example",
      "type": "domain",
      "_marker": "1793491203a1b2c3",
      "last_updated": "2026-11-01T00:00:03Z",
      "...": "every other field returned by the API, declared or not"
    }
  }
]
```

Fields the API did not return are left out. Fields the model does not declare
yet (`reports`, `relations`, ...) are printed as received.

### `transform`

`transform` reads **one** indicator as a JSON object, in the API shape (one
element of an API page's `resources`, such as a row of
`tests/fixtures/indicators_sample.json`), from a file or from standard input,
runs it through the chain of transformers, and prints every step's result as
JSON:

1. `CrowdStrikeIndicatorTransformer`: the STIX 2.1 indicator;
2. `CrowdStrikeAddMalware`: the bundle of that indicator, its Malware objects
   and its `indicates` relationships.

```sh
# Take a domain row of the committed sample as input
python -c "import json; rows = json.load(open('tests/fixtures/indicators_sample.json'))['resources']; print(json.dumps(next(r for r in rows if r['type'] == 'domain')))" > indicator.json

# From a file
PYTHONPATH=src python -m crowdstrike_indicators transform indicator.json

# From standard input
PYTHONPATH=src python -m crowdstrike_indicators transform < indicator.json
```

Standard output is one JSON array, one entry per step, so it can be piped
(`| jq '.[1].output.malware'`). STIX objects appear as their STIX JSON, with
the native properties first, then the CrowdStrike fields no native property
holds, in `x_crowdstrike_*` properties:

```json
[
  {
    "step": 1,
    "transformer": "CrowdStrikeIndicatorTransformer",
    "output": {
      "type": "indicator",
      "id": "indicator--f975582d-ec64-5f6c-ac8c-1fdea0f69e0b",
      "name": "malicious-7.example",
      "pattern": "[domain-name:value = 'malicious-7.example']",
      "...": "...",
      "x_crowdstrike_malware_families": ["ExampleFamily4", "ExampleFamily6", "ExampleFamily7"]
    }
  },
  {
    "step": 2,
    "transformer": "CrowdStrikeAddMalware",
    "output": {
      "indicator": {"...": "the indicator of step 1, unchanged"},
      "malware": [
        {"type": "malware", "id": "malware--06d31b08-d590-5298-8440-23b86775f679", "name": "ExampleFamily4", "is_family": true, "...": "..."}
      ],
      "relationships": [
        {"type": "relationship", "relationship_type": "indicates", "source_ref": "indicator--f975582d-...", "target_ref": "malware--06d31b08-...", "...": "..."}
      ]
    }
  }
]
```

Every step runs before anything is printed: if one fails, standard output
stays empty and the error goes to standard error.

`transform` accepts one object only: a JSON array, such as the `extract`
output, is rejected. It takes `--log-level` too.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success, including an empty result (`[]`) for `extract` |
| 1 | `extract`: API error (status and message on standard error), or an indicator that does not match the model (its `id`, the validation errors and the raw indicator on standard error). `transform`: input that is not valid JSON or not one JSON object, an indicator that does not match the model (reported as for `extract`), or an indicator that cannot be converted (unsupported type, `published_date` after `last_updated`) |
| 2 | usage or configuration error: no or unknown subcommand, bad argument, missing credential, missing `--env-file`, missing `transform` input file |

## Tests

```sh
pytest tests                                    # from this folder
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
  deliberately lenient. Use `--dump-raw` to see the real shape.
- **One invalid indicator stops the run**, with nothing printed on standard
  output. This is on purpose while the model is being refined.
- **No state, no OpenCTI.** Every run is independent. `extract` prints the raw
  API data, and `transform` converts one indicator at a time.
- **A few distinctions do not survive the conversion.** stix2 drops empty
  lists, so an empty CrowdStrike list gives no `x_crowdstrike_*` property and
  reads back as absent. A missing `published_date` reads back as equal to
  `last_updated` (`created` falls back to it), a missing `deleted` as `false`,
  and `malicious_confidence` in lowercase (`HIGH` and `high` both give 85). Real
  data always has these fields, in lowercase, so no value is lost.
