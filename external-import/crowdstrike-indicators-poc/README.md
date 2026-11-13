# CrowdStrike indicators: proof of concept

> **Status: proof of concept, command line only.** Not a connector: it does
> not talk to OpenCTI, keeps no state between runs and builds no STIX yet.

This folder tests a new organization for connectors, built from small
contracts that do not depend on OpenCTI. It starts with the extraction side:
a typed, validated extractor for CrowdStrike Falcon Intelligence indicators,
run from the command line against the real API, so the indicator model can be
refined from actual data.

## Layout

```
src/
  shared/                     contracts, independent of any source
    extractor.py              AbstractExtractor[T: BaseModel]
  crowdstrike_indicators/     CrowdStrike implementation
    models.py                 CrowdStrikeIndicator (Pydantic)
    extractor.py              CrowdStrikeIndicatorExtractor (FalconPy)
    errors.py                 CrowdStrikeAPIError, IndicatorValidationError
    dotenv.py                 minimal .env reader
    cli.py, __main__.py       command line
tests/                        pytest, no network
```

Dependency rule: `shared/` depends only on the standard library and Pydantic,
never on a source. `crowdstrike_indicators/` depends on `shared/`. Runtime
dependencies are `crowdstrike-falconpy`, `pydantic` and `stix2` (stix2 is
reserved for the coming transformer).

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

Run from this folder, with `src` on the Python path:

```sh
# The 50 earliest indicators from 1 November 2026 (UTC) onwards
PYTHONPATH=src python -m crowdstrike_indicators --from 2026-11-01T00:00:00Z --max 50

# Same, and also save the raw API pages, to study the real response shape
PYTHONPATH=src python -m crowdstrike_indicators --from 2026-11-01 --max 50 \
    --dump-raw raw-dumps/first.raw.json

# Credentials from another file, with debug logs
PYTHONPATH=src python -m crowdstrike_indicators --from 2026-11-01 --max 10 \
    --env-file ~/secrets/crowdstrike.env --log-level DEBUG
```

| Option | |
|---|---|
| `--from DATETIME` | required. ISO 8601. Without a timezone, it is read as UTC. |
| `--max N` | required. Maximum number of indicators, 1 or more. |
| `--env-file PATH` | credentials file, `./.env` by default. |
| `--dump-raw PATH` | also write every raw API page received, as a JSON array, even when the extraction fails. `raw-dumps/` and `*.raw.json` are git-ignored. |
| `--log-level LEVEL` | `DEBUG`, `INFO` (default), `WARNING` or `ERROR`. |

### Output

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

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success, including an empty result (`[]`) |
| 1 | extraction failed: API error (status and message on standard error), or an indicator that does not match the model (its `id`, the validation errors and the raw indicator on standard error) |
| 2 | usage or configuration error: bad argument, missing credential, missing `--env-file` |

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
- **No state, no STIX, no OpenCTI.** Every run is independent, and the output
  is the raw API data.
