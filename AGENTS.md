# AGENTS.md — OpenCTI Connectors Monorepo

This file guides **any AI coding agent** (GitHub Copilot, Claude, Cursor, Codex, etc.)
working in this repository. Humans should read [`CONTRIBUTING.md`](./CONTRIBUTING.md).

This is a distilled, actionable summary. **The canonical, in-depth human
documentation lives in [`docs/`](./docs)** — read the relevant file there before
implementing non-trivial logic, and keep this file in sync if you update it:

| Doc                                                                        | Covers                                                             |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| [`docs/01-common-implementation.md`](./docs/01-common-implementation.md)     | Env setup, directory layout, config, connectors-sdk, logging, state |
| [`docs/02-external-import-specifications.md`](./docs/02-external-import-specifications.md) | Scheduling, work management, deduplication                          |
| [`docs/03-internal-enrichment-specifications.md`](./docs/03-internal-enrichment-specifications.md) | Event-driven enrichment, TLP handling, playbooks                    |
| [`docs/04-stream-specifications.md`](./docs/04-stream-specifications.md)     | Live stream listening, event types, sync                            |
| [`docs/05-code-quality-standards.md`](./docs/05-code-quality-standards.md)   | Style, linting, STIX compliance, testing, Docker, metadata           |

> **Gap:** there is currently no dedicated spec doc for `internal-import-file` or
> `internal-export-file` connectors. Their `AGENTS.md` files are distilled from
> `templates/` and existing connector code instead — treat them as lower-confidence.

Each connector-type directory also has its own nested `AGENTS.md` with rules specific
to that architecture. Read **this file plus the one for the folder you're editing**:
`external-import/AGENTS.md`, `internal-enrichment/AGENTS.md`, `stream/AGENTS.md`,
`internal-import-file/AGENTS.md`, `internal-export-file/AGENTS.md`.

## Repository shape

200+ Python 3.11/3.12 connectors integrating OpenCTI with external tools, grouped by
type: `external-import/` (pull, scheduled), `internal-enrichment/` (event-driven,
enriches existing entities), `stream/` (real-time sync), `internal-import-file/` /
`internal-export-file/` (file conversion). Shared code lives in `connectors-sdk/` and
`shared/`. New connectors are scaffolded with `templates/create_connector_dir.sh`.

Standard connector layout:
```
<type>/<connector-name>/
├── __metadata__/connector_manifest.json   # title, description, container_type, use_cases...
├── src/connector/{connector.py, converter_to_stix.py, settings.py}
├── src/main.py
├── tests/
├── config.yml.sample / .env.sample
├── Dockerfile / docker-compose.yml
└── README.md
```

## Configuration (Pydantic + connectors-sdk)

Define settings in `src/connector/settings.py` using `BaseConnectorSettings` /
`BaseConfigModel` from `connectors-sdk`. Config is auto-discovered: `config.yml` takes
precedence over `.env`, both are overridden by environment variables. Env var names are
`SECTION_FIELD` in uppercase (e.g. `my_connector.api_key` → `MY_CONNECTOR_API_KEY`).
Never hardcode secrets — use `.env.sample`/`config.yml.sample` as templates only.

## STIX objects: deterministic IDs are CRITICAL

**Never let `stix2` auto-generate an object ID.** OpenCTI deduplicates via a
deterministic `standard_id` derived from each entity's "ID Contributing Properties"
(e.g. `name` for Malware, `pattern` for Indicator, `name`+`published` for Report).
Random IDs bypass this, causing the `x_opencti_stix_ids` list to grow unboundedly on
every re-import → memory bloat and Redis stream degradation.

```python
# Preferred: connectors-sdk models (deterministic ID built in)
from connectors_sdk.models import IPV4Address, OrganizationAuthor, TLPMarking
author = OrganizationAuthor(name="Example Author")
ip = IPV4Address(value="127.0.0.1", author=author, markings=[TLPMarking(level="amber+strict")])
stix_object = ip.to_stix2_object()

# Accepted: stix2 + pycti generate_id()
import stix2
from pycti import Indicator
indicator = stix2.Indicator(
    id=Indicator.generate_id("[domain-name:value = 'evil.com']"),
    pattern="[domain-name:value = 'evil.com']",
    pattern_type="stix",
)
```
The custom pylint plugin (`shared/pylint_plugins/check_stix_plugin`, rule
`no_generated_id_stix`) enforces this — run it on any connector code you touch that
creates STIX objects (see below).

## Logging & error handling

Always log via `self.helper.connector_logger.{debug,info,warning,error}(message, {dict of context})`
— never f-string interpolation into the message. Wrap `main.py`'s entrypoint in
try/except with `traceback.print_exc(); exit(1)`. Use `tenacity` for retry with
exponential backoff and `limiter` for API rate limiting.

## Formatting, linting, testing (run before every commit)

```bash
# Format (required, CI fails otherwise)
isort --profile black --line-length 88 .
black .

# Lint
flake8 --ignore=E,W .

# STIX ID plugin — mandatory whenever you create/modify STIX objects
cd shared/pylint_plugins/check_stix_plugin && pip install -r requirements.txt
PYTHONPATH=. python -m pylint <path/to/connector> \
  --disable=all --enable=no_generated_id_stix,no-value-for-parameter,unused-import \
  --load-plugins linter_stix_id_generator

# Tests (isolated venv per connector)
bash run_test.sh ./<type>/<connector-name>/tests/test-requirements.txt
```

## Metadata & docs

Update `__metadata__/connector_manifest.json` (title, description, `container_type`,
`use_cases`, `solution_categories`, `playbook_supported`, etc.) for any new/modified
connector, and keep `README.md` complete (config table, behavior, troubleshooting).
Never commit real secrets in `.env.sample`/`config.yml.sample` — use `ChangeMe`.

## PR conventions

Conventional Commits with an issue reference (`type(scope): description (#issue)`),
GPG-signed commits, PR title ends with the issue reference. See `CONTRIBUTING.md` and
`.github/LABELS.md`.
