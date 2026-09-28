# OpenCTI connectors

Monorepo of about 300 Python connectors that integrate the OpenCTI threat
intelligence platform with external tools and data sources. Each connector is
an independent Python project with its own dependencies, tests and Docker
image. There is no root `pyproject.toml`: never add one (see the comment in
`.isort.cfg` for why).

## Layout

```text
connectors-sdk/          Shared SDK: STIX models with deterministic IDs, settings, base connectors
external-import/         Pull data from an external source into OpenCTI
internal-enrichment/     Enrich existing OpenCTI entities on demand
internal-import-file/    Parse uploaded files into STIX
internal-export-file/    Export OpenCTI data to files
stream/                  Consume the OpenCTI live stream and push to a third party
templates/               One reference template per connector type
shared/pylint_plugins/   STIX ID pylint checker (run in CI)
shared/tools/            Manifest/schema generators, connector-linter, CI helpers
.github/scripts/         Build/test/lint matrix generation, release tooling
```

A connector looks like this. `templates/<type>/` is the source of truth for
the current layout, so read it before creating or restructuring a connector.

```text
<type>/<name>/
├── __metadata__/
│   ├── connector_manifest.json      Hand-written catalog metadata
│   ├── connector_config_schema.json Generated from settings.py, do not edit
│   ├── CONNECTOR_CONFIG_DOC.md      Generated from settings.py, do not edit
│   └── logo.png
├── src/
│   ├── connector/
│   │   ├── settings.py              Pydantic config (connectors-sdk BaseConnectorSettings)
│   │   └── ...
│   ├── main.py                      Entry point
│   └── requirements.txt
├── tests/
│   ├── conftest.py
│   ├── tests_connector/
│   └── test-requirements.txt        Starts with -r ../src/requirements.txt
├── config.yml.sample
├── docker-compose.yml
├── Dockerfile                       Also sets the Python version used to build
├── Dockerfile_fips                  Optional: its presence triggers a FIPS image build
└── README.md
```

Older connectors still use `get_config_variable`, a monolithic single file or
`.env.sample`. Do not copy those patterns into new code: follow the template.

## Writing connector code

- **Deterministic STIX IDs, always.** Never let the `stix2` library generate
  an ID. Use `connectors_sdk.models` (preferred) or pycti's `generate_id()`
  helpers such as `Identity.generate_id(...)`. A random ID creates a
  duplicate entity in OpenCTI on every run, and the STIX ID pylint job fails
  the PR.
- **Configuration goes through Pydantic settings** in `src/connector/settings.py`,
  built on `connectors_sdk.BaseConnectorSettings`. Values come from environment
  variables or `config.yml`. Mark secrets as `SecretStr`.
- **New external-import connectors** use `connectors_sdk.ExternalImportConnector`
  with data processors (`collect()` then `transform()`) and a `ConnectorState`.
  The SDK owns the scheduling loop: do not write your own. See
  `templates/external-import/src/main.py`.
- Prefer SDK models over hand-built STIX dicts:

  ```python
  from connectors_sdk.models import IPV4Address, OrganizationAuthor, TLPMarking

  author = OrganizationAuthor(name="Example Author")
  ip = IPV4Address(
      value="127.0.0.1",
      author=author,
      markings=[TLPMarking(level="amber+strict")],
  )
  stix_object = ip.to_stix2_object()
  ```

- Keep `requirements.txt` minimal and accurate. The `deptry` CI job flags
  unused and missing dependencies per changed connector.
- Never commit secrets. Samples (`config.yml.sample`, `docker-compose.yml`)
  hold placeholders only.
- **Logging:** static message plus a context dict, never an f-string:
  `self.logger.info("Reports fetched", {"count": len(reports)})` (use
  `helper.connector_logger` in legacy connectors). Log a handled or skipped
  error at WARNING, keep ERROR for unexpected failures at the top level.
- **Errors:** use the SDK exceptions (`ConfigValidationError` at startup,
  `DataRetrievalError` for source failures, `UseCaseError` for conversion
  failures) and always `raise ... from err`. See
  `connectors-sdk/docs/HOW-TO-Handle-errors-in-connectors.md`.
- Never pass a `datetime` to `Note.generate_id()`: use `created=None`. A
  timestamp creates a new note on every run and floods the RabbitMQ queue.
- Environment variables are `<SECTION>_<FIELD>` in upper case, where the
  section is the settings attribute name (`connector`, `opencti`, or the
  connector's own section).
- Avoid `helper.api` queries from connector code: they are slow and couple the
  connector to the platform schema.

### External-import connectors

The base class owns the run loop, work management, bundle sending and state
persistence. A data processor only fetches and converts.

- `collect()` returns raw data, with no STIX. `transform()` converts, with no
  network call. Build the client, author and marking once in `post_init()`.
- Never call `send()`, `initiate_work()`, `to_processed()`,
  `stix2_create_bundle()`, `send_stix2_bundle()` or `state.save()` from a
  processor, and never set `last_run`.
- Every `transform()` result includes the author and the marking objects,
  otherwise references to them break (`MISSING_REFERENCE_ERROR`). Return `[]`
  when there is nothing to send.
- Skip and log (WARNING) a single item that fails to convert instead of
  failing the whole run, and advance a checkpoint only past items that
  converted.
- State is saved once, after every processor succeeds. An exception in any
  processor discards all checkpoints of that run.
- State fields are JSON-friendly types (`str`, `int`, timezone-aware
  `datetime`, `None`) defaulting to `None`. State holds checkpoints, not a
  cache.
- No `while True`, `time.sleep()` or `force_ping()`. `duration_period` is an
  ISO-8601 duration; a zero duration means run once and exit.
- Start-date settings default to a relative duration (`P30D`) through
  `DatetimeFromIsoString`, not a hard-coded date.
- For large or paginated sources, make `collect()` and `transform()`
  generators and keep bundles under about 10,000 objects.

Details: `docs/02-external-import-specifications.md`.

### Internal-enrichment connectors

- Check the entity scope from the `data["entity_id"]` prefix against
  `helper.connect_scope`.
- Check the TLP with `helper.check_max_tlp(entity_tlp, max_tlp)` before any
  external API call. Both values must be in `TLP:XXX` form: pycti raises
  `KeyError` on `"amber+strict"`.
- When the message comes from a playbook (`data.get("event_type")` is falsy)
  and the entity is out of scope, send `data["stix_objects"]` back unchanged.
  Otherwise the playbook stalls.
- Set `playbook_compatible=True` on the helper and `"playbook_supported": true`
  in the manifest only when every code path sends a bundle, and keep the
  original `stix_objects` in it.
- Send results only through `stix2_create_bundle()` and `send_stix2_bundle()`.
  Direct API writes skip confidence checks and deduplication.
- Default `CONNECTOR_AUTO` to `false` for paid or quota-limited sources.

Details: `docs/03-internal-enrichment-specifications.md`.

### Stream connectors

- `msg.data` is a JSON string: parse it with `json.loads(msg.data)["data"]`,
  then branch on `msg.event` (`create`, `update`, `delete`).
- Reject a missing or `ChangeMe` `helper.connect_live_stream_id` at startup.
- The helper stores the stream position (`start_from`, `recover_until`) in the
  connector state. Merge into `helper.get_state()` before `set_state()`,
  never overwrite it with your own dict.

Details: `docs/04-stream-specifications.md`.

### Specification docs are partly stale

`docs/`, `CONTRIBUTING.md` and `templates/README.md` still describe the old
layout in places (`connector.py`, `converter_to_stix.py`, `entrypoint.sh`,
`schedule_iso`, `pip install`, random `uuid4()` relationship IDs). When they
disagree with `templates/<type>/`, the SDK code or this file, those three win.

## Changing connectors-sdk

- Read `connectors-sdk/TDRs/` first: they record the design decisions
  (Pydantic models, settings, state, error handling, coverage).
- The SDK test session also runs `ruff check` (Google-style docstrings
  required) and strict `mypy`, and fails if either fails. Coverage must stay
  at 100%.
- New model: one file per model under `connectors_sdk/models/`, exported from
  `connectors_sdk/models/__init__.py`, listed in
  `tests/test_models/test_api.py`, with its own `tests/test_models/test_<name>.py`.
  `connectors_sdk/models/hostname.py` is a small example.
- Renamed or removed config keys go through `connectors_sdk.settings.deprecations`,
  not hand-written alias fallbacks.
- The SDK how-tos for new observables and relationships reference modules that
  no longer exist (`models/octi/...`, `MODEL_REGISTRY`). Follow the rule above.

## Creating a connector

```bash
cd templates && sh create_connector_dir.sh -t external-import -n myconnector
```

Valid types: `external-import`, `internal-enrichment`, `stream`,
`internal-import-file`, `internal-export-file`. Then replace every
`Template`/`template` reference, generate a UUIDv4 for the connector `id`
default, fill in `__metadata__/connector_manifest.json`, and resolve the
`TODO` checklists left in the template files.

Manifest rules (`__metadata__/connector_manifest.json`):

- `use_cases` and `solution_categories`: 1 to 3 values each, from the fixed
  lists in `CONTRIBUTING.md`.
- `short_description`: 250 characters or fewer.
- Logo: square PNG or JPEG, at least 96x96.
- Never change `verified`, `last_verified_date` or `manager_supported`:
  maintainers own them.

## Validation commands

Run these from the repository root before proposing a commit. CI runs the same
checks with Python 3.12 and the pinned versions in `ci-requirements.txt`.

Format (isort first, then black):

```bash
uvx isort==7.0.0 --profile black --line-length 88 external-import/myconnector
uvx black==26.5.1 external-import/myconnector
```

Lint:

```bash
uvx flake8 --ignore=E,W external-import/myconnector
```

STIX ID checker (mandatory when the change creates STIX objects):

```bash
cd shared/pylint_plugins/check_stix_plugin && uv run --no-project --with-requirements requirements.txt env PYTHONPATH=. pylint ../../../external-import/myconnector --disable=all --enable=no_generated_id_stix,no-value-for-parameter,unused-import --load-plugins linter_stix_id_generator
```

Verified linter (VC checks, run in CI on every manager-supported connector):

```bash
cd shared/tools/connector_linter && uv run connector-linter check ../../../external-import/myconnector
```

Tests, in an isolated venv created by the script:

```bash
bash run_test.sh ./external-import/myconnector/tests/test-requirements.txt
```

Things to know about `run_test.sh`:

- It computes `git merge-base origin/master HEAD`, so `origin/master` must
  exist locally (`git fetch origin master` in a shallow clone).
- It skips a connector with no changes since that merge base. Set
  `CIRCLE_BRANCH=master` to force the run (legacy variable name, still read).
- It reinstalls pycti from the `opencti` repository (`client-python`
  subdirectory) at `RELEASE_REF` (default `master`), and installs the local
  `connectors-sdk` when the connector depends on it. A test that passes with
  the pinned pycti can still fail here.
- Coverage and JUnit output go to `test_outputs/`.

Changes to `connectors-sdk/` must keep 100% test coverage
(`--cov-fail-under=100` in its `pyproject.toml`).

## Generated files

`connector_config_schema.json`, `CONNECTOR_CONFIG_DOC.md` and the root
`manifest.json` are generated. The `build-manifest.yml` workflow regenerates
and commits them, so never edit them by hand. To regenerate locally after
changing `settings.py`:

```bash
mise run gs external-import/myconnector
```

`gs` is the `generate_config_schema` mise task (`.mise/tasks/`); it takes the
connector path and does not prompt. The equivalent `make` targets
(`connector_config_schema`, `connectors_config_schemas`, `connector_manifest`,
`connectors_manifests`, `global_manifest`) prompt for the connector folder
name, so they need piped answers: `printf 'myconnector\ny\n' | make connector_config_schema`.

The generator installs `connectors-sdk` from GitHub `master`, which pins an
exact pycti version. If the connector's `requirements.txt` pins an older
pycti, dependency resolution fails and generation stops. Rebase on the latest
`master` before regenerating.

## CI overview

Workflows live in `.github/workflows/`. On a pull request, only changed
connectors are built and tested, unless `connectors-sdk/` or files outside the
connector directories changed.

- `ci-lint-format.yml`: isort and black check, flake8, STIX ID pylint.
- `ci-tests-connectors.yml`: `run_test.sh` per changed connector.
- `ci-connector-verified-linter.yml`: connector-linter on changed connectors,
  results posted as a PR comment.
- `ci-unused-deps.yml`: deptry on changed connectors.
- `ci-check-connector-identity-uniqueness.yml`: no two manifests share an
  identity.
- `gh-pr-check-conventions.yml`: signed commits, linked issue, PR title format.
- `build-*.yml`, `release-*.yml`: multi-arch image builds and releases, run
  on `master`, `release/*`, `lts/*` and tags.

<!-- filigran-conventions:start -->
## Commit, PR & issue conventions

All commits, pull requests and issues in this repository follow the
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
specification with a GitHub issue reference:

```text
type(scope?)!?: description (#issue)
```

- Types: `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `perf`, `test`,
  `build`, `ci`, `revert`.
- The description starts with a lowercase letter and has no trailing period;
  preserve acronyms and proper nouns.
- The old `[backend]` / `[frontend]` bracket prefixes are discontinued. Use a
  Conventional Commits scope instead, typically the connector name, for
  example `fix(mandiant): handle empty report list (#1234)`.
- Pull request titles **must** end with the related issue reference, e.g.
  `(#1234)`, and every pull request must be linked to an issue.
- Sign your commits. CI rejects unsigned commits.

When generating commit messages, PR titles or issue titles, always follow this
convention. See [`.github/LABELS.md`](.github/LABELS.md) for the full title and
label taxonomy.
<!-- filigran-conventions:end -->

## Pull requests

- One GitHub issue per pull request, referenced at the end of the title.
- Fill in `.github/PULL_REQUEST_TEMPLATE.md` (proposed changes, related
  issues, checklist) rather than writing a free-form body.
- Labels: exactly one ownership label (`filigran team` or `community`), plus
  `vibe-coded` for an AI-assisted pull request. Type, area and workflow labels
  are for issues only. Language and `dependencies` labels are automatic.

Checklist before opening one:

- Formatting, flake8, STIX ID pylint and connector-linter pass locally.
- Tests pass with `run_test.sh`, and new behaviour has tests.
- `connector_manifest.json`, `README.md` and `config.yml.sample` reflect the
  change. Schemas regenerated if `settings.py` changed.
- The image builds: `docker build -t myconnector-test external-import/myconnector`.
