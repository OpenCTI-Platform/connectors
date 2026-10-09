# Manager-supported migration procedure

Migrates one legacy OpenCTI connector to manager-supported mode: its
configuration is loaded and validated by Pydantic settings built on
`connectors_sdk.BaseConnectorSettings`, the pycti helper is built from
`settings.to_helper_config()`, and the connector ships a generated config
schema. The rest of the connector stays as it is.

Paths below are relative to the repository root. `<path>` is the connector
directory (for example `external-import/vxvault`) and `<name>` its last
segment (`vxvault`), used as the commit scope.

## Inputs

- **Connector path** (required).
- **GitHub issue number** (required): every commit message ends with
  `(#<issue>)`. If it is missing, stop and ask for it.
- **Working directory** (optional): when the caller runs several migrations
  in parallel, it gives each one its own git worktree or jj workspace. Do
  every read, edit, validation and commit inside that directory.

## Scope

Change how configuration is loaded and read. Keep the code shape.

In scope:

1. Normalize the config files and requirements.
2. Add a `settings.py` that mirrors the existing variables.
3. Swap config loading for the settings in the existing code, in place.
4. Set `manager_supported` to `true` in the manifest.
5. Generate the config schema and its documentation.
6. Add tests for the settings and their wiring.

Out of scope (the broader "verified" work, done separately):

- Restructuring into a `src/connector/` package, splitting files, adding an
  entry point, renaming files or classes, moving code.
- Replacing the scheduling loop with `schedule_iso` or an SDK base connector.
- Refactoring logging, converters or STIX ID generation.

If the connector needs any of this to work, stop and report it instead of
widening the change.

## Pre-flight

Read before editing:

1. `src/`: find the module that loads `config.yml`, calls
   `get_config_variable(...)` and builds `OpenCTIConnectorHelper`. That is
   where the settings get wired in.
2. `docker-compose.yml`: list every environment variable. Custom variables
   (not `OPENCTI_*` or `CONNECTOR_*`) share a prefix that becomes the settings
   section: `VXVAULT_URL`, `VXVAULT_SSL_VERIFY` give the section `vxvault`.
3. `config.yml.sample` and `.env.sample` when present.
4. `__metadata__/connector_manifest.json`: current `manager_supported` value
   and display name.
5. The connector type, from the parent directory: `external-import`,
   `internal-enrichment`, `stream`, `internal-export-file`,
   `internal-import-file`.
6. The README configuration tables.

Infer field types from the legacy calls:

```python
get_config_variable("ENV_VAR_NAME", ["section", "key"], config, isNumber, default, required)
```

- `isNumber=True` gives `int`.
- `default` gives the field default (`None` when absent).
- `required=True` gives a field with no default.
- `true`/`false` values give `bool`.
- Names containing `token`, `key`, `secret` or `password` give `SecretStr`.
- Everything else is `str`.

## Commits

One commit per step, made as soon as the step is done and before the next
one starts. Each commit is a reviewable unit, so never batch steps.

Before every commit, format the connector (versions pinned by CI, see
`AGENTS.md`):

```bash
uvx isort==7.0.0 --profile black --line-length 88 <path>
uvx black==26.5.1 <path>
```

Then commit with the repository's VCS:

- jj (a `.jj/` directory exists at the root): `jj commit -m "<message>"`
- git: `git add <path> && git commit -m "<message>"`

Messages, in order:

```text
1. feat(<name>): normalize config files for manager-supported migration (#<issue>)
2. feat(<name>): add Pydantic settings for manager-supported mode (#<issue>)
3. feat(<name>): use Pydantic settings in existing connector code (#<issue>)
4. feat(<name>): set manager_supported to true in connector manifest (#<issue>)
5. feat(<name>): generate connector config schema for manager-supported mode (#<issue>)
6. feat(<name>): add unit tests for manager-supported mode (#<issue>)
```

Do not push and do not open a pull request. CI rejects unsigned commits, so
the person who ships the branch makes sure the commits are signed.

## Step 1: normalize config files

- Rename `docker-compose.yaml` to `docker-compose.yml` and
  `config.yaml.sample` to `config.yml.sample` if needed.
- Turn commented-out real settings (`#- VAR=...`, `#key: value`) back into
  entries, so Step 2 sees every variable.
- Remove `CONNECTOR_TYPE`: the SDK sets the type.
- Write booleans as `true`/`false`.
- Create `.env.sample` from the docker-compose variables only when neither
  `config.yml.sample` nor `.env.sample` exists.
- Append to `src/requirements.txt` if missing:

  ```text
  pydantic >=2.8.2, <3
  connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk
  ```

Commit 1.

## Step 2: add settings.py

Create `settings.py` next to the module that loads the config: `src/settings.py`
for a flat layout, `src/<pkg>/settings.py` when the code already lives in a
package. Do not create a new package.

Mirror the existing variables one to one. Keep the connector's own field
names, even odd ones; renames are follow-up work (see the end of this file).

```python
"""OpenCTI <Name> connector settings module."""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class <Name>ConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the <Name> connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="<fresh UUIDv4>",
    )
    name: str = Field(
        description="The name of the connector.",
        default="<display name>",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["<scope>"],
    )


class <Name>Config(BaseConfigModel):
    """Settings specific to the <Name> connector."""

    api_key: SecretStr = Field(description="...")  # no default: required
    ssl_verify: bool = Field(description="...", default=True)


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the <Name> connector."""

    connector: <Name>ConnectorConfig = Field(default_factory=<Name>ConnectorConfig)
    <section>: <Name>Config = Field(default_factory=<Name>Config)
```

Base class per type: `BaseExternalImportConnectorConfig`,
`BaseInternalEnrichmentConnectorConfig`, `BaseStreamConnectorConfig`,
`BaseInternalExportFileConnectorConfig`,
`BaseInternalImportFileConnectorConfig`.

### The `connector.id` default is mandatory

The SDK declares `connector.id` required with no default, so without this
override the connector cannot be deployed from the catalog without manual
input. No linter catches a missing override.

1. Generate the value: `python3 -c "import uuid; print(uuid.uuid4())"`. Never
   copy one from another connector and never type a pattern by hand.
2. Check that it is unique: `grep -rI "<uuid>" --include='*.py' . | grep -v '/.venv/'`
   must return only this `settings.py`.
3. If the connector already declares an `id` default, keep it, but run the
   same uniqueness check.

Keep `CONNECTOR_ID=ChangeMe` in `docker-compose.yml` and the samples:
connector-linter (VC104) accepts `ChangeMe`, and a real UUID there would give
every deployment the same identity. The schema generator always drops
`CONNECTOR_ID`, so the default does not show in the schema.

### Scheduling of external-import connectors

`BaseExternalImportConnectorConfig.duration_period` is required with no
default. The connector keeps its own loop, so pick one of these:

- **The connector has an interval variable** (`<SECTION>_INTERVAL`,
  `<SECTION>_INTERVAL_SEC`, ...): make `CONNECTOR_DURATION_PERIOD` the
  setting and keep the legacy variable working through `DeprecatedField`.
  Step 3 then reads the sleep duration from `duration_period`; the loop
  itself does not change.

  ```python
  from datetime import timedelta

  from connectors_sdk import DeprecatedField


  class <Name>ConnectorConfig(BaseExternalImportConnectorConfig):
      # id, name, scope as above
      duration_period: timedelta = Field(
          description="The period of time to await between two runs of the connector.",
          default=timedelta(minutes=5),  # the legacy interval default
      )


  class <Name>Config(BaseConfigModel):
      interval_sec: int | None = DeprecatedField(
          deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
          new_namespace="connector",
          new_namespaced_var="duration_period",
          new_value_factory=lambda seconds: timedelta(seconds=int(seconds)),
      )
  ```

  Match the unit of `new_value_factory` to the legacy variable (seconds,
  minutes, hours, days). `BaseConnectorSettings` migrates the value and warns,
  so no validator is needed.

- **The connector has no interval variable** (fixed sleep, cron, run once):
  hide the inherited field so the schema does not advertise a setting that
  does nothing.

  ```python
  from pydantic.json_schema import SkipJsonSchema


  class <Name>ConnectorConfig(BaseExternalImportConnectorConfig):
      # id, name, scope as above
      duration_period: SkipJsonSchema[None] = Field(
          description="Not used: the connector keeps its own scheduling.",
          default=None,
      )
  ```

### Other type-specific points

- **Stream:** `live_stream_id` stays required. Do not give it a default.
- **`CONNECTOR_UPDATE_EXISTING_DATA`** is deprecated: do not add a field for it.
  Step 3 stops reading and passing it.

### Config files and README

- Every setting appears in `docker-compose.yml`, and in `config.yml.sample` or
  `.env.sample` when they exist.
- A setting with a default is present but commented out, with the default
  from `settings.py` as its value. `settings.py` is the source of truth.
- A required setting is uncommented with the value `ChangeMe`.
- Update the README configuration tables (default, mandatory) to match.

### Make `ConnectorSettings` importable by the schema generator

The generator imports `from src import ConnectorSettings`, then
`from src.main import ConnectorSettings`. When neither works, add a minimal
`src/__init__.py`, using the same import style as the connector's entry point:

```python
from <pkg>.settings import ConnectorSettings  # or: from settings import ConnectorSettings

__all__ = ["ConnectorSettings"]
```

The generator tries `ConfigLoader` before `ConnectorSettings`. If
`src/__init__.py` exports a legacy `ConfigLoader`, replace that export,
otherwise the schema is built from the old config.

This `src/__init__.py` and `settings.py` are the only new source files of the
migration.

Commit 2.

## Step 3: use the settings in the existing code

Edit the existing module in place, with the smallest change that swaps the
config source.

| Legacy code | Replacement |
|---|---|
| `yaml.load(open(config_file_path), ...)` and the path plumbing | Remove |
| `OpenCTIConnectorHelper(config)` | `self.config = ConnectorSettings()`, then `OpenCTIConnectorHelper(config=self.config.to_helper_config())` |
| `get_config_variable("<SECTION>_<KEY>", ...)` | `self.config.<section>.<key>` |
| `get_config_variable("CONNECTOR_<KEY>", ...)` | `self.config.connector.<key>` |
| A `SecretStr` value passed to a client | `.get_secret_value()` |
| A legacy interval read | `int(self.config.connector.duration_period.total_seconds())` (or the unit the loop expects) |
| `update=update_existing_data` in `send_stix2_bundle` | Remove the argument |

- Build `ConnectorSettings()` where the config was loaded before (usually
  `__init__`, sometimes the `__main__` block).
- Keep `playbook_compatible=True` on the helper when it is already there.
- Keep the scheduling loop, the logging calls, the class names and the
  `if __name__ == "__main__"` block.
- Keep files that become unused (a legacy config loader, for example) and
  list them in the report: deleting them is a separate decision.
- If `yaml` is no longer imported anywhere in `src/`, remove `pyyaml` from
  `requirements.txt` (the deptry CI job flags unused dependencies).

Commit 3.

## Step 4: manifest

In `__metadata__/connector_manifest.json`, set `"manager_supported": true`.
Change nothing else: `verified`, `last_verified_date` and the other fields
belong to maintainers.

Commit 4.

## Step 5: generate the config schema

From the repository root:

```bash
mise run gs <path>
```

It writes `__metadata__/connector_config_schema.json` and
`__metadata__/CONNECTOR_CONFIG_DOC.md`. Never edit those by hand.

- It must exit 0. An `ImportError` on `ConnectorSettings` means the Step 2
  export is wrong: fix it in Step 2's change (or a fix commit) and rerun.
- It installs `connectors-sdk` from GitHub `master`, which pins an exact
  pycti. If the connector pins an older pycti, dependency resolution fails:
  report it rather than bumping pycti inside this migration.
- Check the result: `required` lists `OPENCTI_URL`, `OPENCTI_TOKEN` and the
  connector's required variables, and every setting has a property.

Commit 5.

## Step 6: tests

Follow `templates/<type>/tests/` for layout and pins.

`tests/test-requirements.txt`:

```text
-r ../src/requirements.txt
pytest==<same pin as templates/<type>/tests/test-requirements.txt>
```

`tests/conftest.py`:

```python
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
```

Keep any existing tests and test files.

### tests/tests_connector/test_settings.py

Each test subclasses `ConnectorSettings` and overrides `_load_config_dict` to
return a dict, so no environment variable or file is read:

```python
class FakeConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(settings_dict)
```

Define `MINIMAL_VALID_SETTINGS_DICT` (OpenCTI URL and token, empty `connector`
section, required custom fields only) and cover:

1. `test_settings_should_accept_valid_input`, parametrized with every field
   set, and with `MINIMAL_VALID_SETTINGS_DICT`.
2. `test_settings_should_apply_defaults`: the minimal dict yields the
   documented defaults (name, scope, custom fields, `duration_period`).
3. `test_settings_should_default_connector_id`: with an empty `connector`
   section, `settings.connector.id` equals the UUID from `settings.py` and
   `UUID(settings.connector.id).version == 4`.
4. `test_settings_should_raise_when_invalid_input`, parametrized with `{}`, a
   missing OpenCTI token, `connector.id` given as an int, and each missing
   required custom field. Assert `ConfigValidationError` with
   `"Error validating configuration"` in the message.
5. With a `DeprecatedField` interval:
   - the legacy value alone migrates to `duration_period`, under
     `pytest.warns(UserWarning, match="<section>.<field>")`;
   - when both are set, `duration_period` wins, under
     `pytest.warns(UserWarning, match="Using only 'connector.duration_period'")`.

### tests/test_main.py

Mock the heavy parts of the helper:

```python
@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())
```

Define a `StubConnectorSettings` with realistic values from
`docker-compose.yml` and every non-deprecated field of `settings.py`, then:

1. `test_connector_settings_is_instantiated`: `to_helper_config()` returns a
   dict.
2. `test_opencti_connector_helper_is_instantiated`: a helper built from
   `to_helper_config()` exposes the URL, token, connector id, name, scope and
   log level.
3. `test_connector_is_instantiated`: the existing class builds its own
   settings, so patch the name it imports
   (`monkeypatch.setattr("<module>.ConnectorSettings", StubConnectorSettings)`),
   mock the external API client, instantiate the class as the entry point
   does, and assert that `config` is the stub, the helper comes from it, and
   the custom values reach the objects that use them.

Commit 6.

## Validation

From the repository root:

```bash
uvx flake8 --ignore=E,W <path>
cd shared/tools/connector_linter && uv run connector-linter check ../../../<path>
python3 .github/scripts/deptry_scan.py <path>
bash run_test.sh ./<path>/tests/test-requirements.txt
```

- `run_test.sh` needs git and an `origin/master` ref. In a jj workspace with
  no `.git`, run the tests in a throwaway environment instead:

  ```bash
  uv venv -p 3.12 /tmp/<name>-venv
  uv pip install --python /tmp/<name>-venv -q -r <path>/tests/test-requirements.txt
  uv pip install --python /tmp/<name>-venv -q ./connectors-sdk
  /tmp/<name>-venv/bin/python -m pytest <path>/tests -q
  rm -rf /tmp/<name>-venv
  ```

- connector-linter now runs on this connector in CI (it is manager-supported).
  Fix findings caused by the migration. Report the others without fixing
  them: they belong to the verified work.
- Rerun the `connector.id` uniqueness check.

A failure caused by the migration gets fixed and committed as
`fix(<name>): <what> (#<issue>)`, or folded into the step that introduced it
when the VCS makes that easy (`jj squash --into <change>`).

## Report

| Step | Commit | Status |
|---|---|---|
| 1. Config files | `<id>` | done / skipped (why) |
| ... | | |

Then:

- Test count and the result of each validation command.
- The generated `connector.id` UUID.
- Files left unused by the migration (kept on purpose).
- Follow-up candidates spotted but not done: variables with a wrong or
  copied prefix (`CONNECTOR_TEMPLATE_*`), connector-linter findings, verified
  work (restructuring, `schedule_iso`, logging, STIX IDs).

## Follow-ups, only when asked

Reviews often ask for these after the six steps. Each one is its own commit.

- **Rename a variable** (wrong prefix, misleading name): add the new field
  and turn the old one into a `DeprecatedField` pointing at it
  (`new_namespace`, `new_namespaced_var`), update the samples, README, schema
  and tests. Never hand-write alias fallbacks.
- **Delete the legacy config loader** once nothing imports it.
- **Fix behavior the migration exposed** (for example an internal-enrichment
  connector that does not send the original bundle back to a playbook):
  follow the rules for the connector type in `AGENTS.md`.
