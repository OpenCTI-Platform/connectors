# CrowdStrike indicators: proof of concept

> **Status: proof of concept, command line only.** Not a connector: it does
> not talk to OpenCTI and keeps no state between runs.

This folder tests a new organization for connectors, built from small
contracts that do not depend on OpenCTI:

1. an extractor: typed, validated CrowdStrike Falcon Intelligence indicators,
   run from the command line against the real API, so the indicator model can
   be refined from actual data;
2. a transformer: each indicator converted into one STIX 2.1 indicator that
   loses nothing of the source data.

## Layout

```
src/
  shared/                     contracts, independent of any source
    extractor.py              AbstractExtractor[T: BaseModel]
    transformer.py            AbstractTransformer[InputType, OutputType]
  crowdstrike_indicators/     CrowdStrike implementation
    models.py                 CrowdStrikeIndicator (Pydantic)
    extractor.py              CrowdStrikeIndicatorExtractor (FalconPy)
    stix.py                   CrowdStrikeStix2Indicator (stix2 Indicator subclass)
    transformer.py            CrowdStrikeIndicatorTransformer
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

- **Nothing is lost.** Every CrowdStrike field is kept as is in
  `x_crowdstrike_<field>`, named after the API field without its leading
  underscore (`_marker` becomes `x_crowdstrike_marker`). Fields the model does
  not declare (`reports`, `relations`, `scope`, ...) are kept together in
  `x_crowdstrike_extra`.
- **Native STIX is filled where the meaning matches:**

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

The STIX `id` is the one pycti's `Indicator.generate_id(pattern)` gives, a
UUIDv5 over the canonicalized pattern, reimplemented with stix2 alone. The
existing CrowdStrike connector builds its patterns the same way, so an
indicator gets the id it already has in OpenCTI.

`stix2.parse` rebuilds a plain `Indicator`, which accepts the
`x_crowdstrike_*` properties only with `allow_custom=True`.

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
and prints its STIX 2.1 indicator as JSON.

```sh
# Take a domain row of the committed sample as input
python -c "import json; rows = json.load(open('tests/fixtures/indicators_sample.json'))['resources']; print(json.dumps(next(r for r in rows if r['type'] == 'domain')))" > indicator.json

# From a file
PYTHONPATH=src python -m crowdstrike_indicators transform indicator.json

# From standard input
PYTHONPATH=src python -m crowdstrike_indicators transform < indicator.json
```

The output is one STIX object, with the native properties first and every
CrowdStrike field in `x_crowdstrike_*` properties:

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--...",
    "name": "malicious-7.example",
    "pattern": "[domain-name:value = 'malicious-7.example']",
    "...": "...",
    "x_crowdstrike_id": "domain_malicious-7.example",
    "x_crowdstrike_marker": "...",
    "x_crowdstrike_labels": [{"name": "...", "created_on": "..."}]
}
```

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
- **Empty list and absent field look the same in STIX.** stix2 drops empty
  lists, so an empty CrowdStrike list gives no `x_crowdstrike_*` property, and
  reads back as absent. In real data every list field is always present, so no
  value is lost.
