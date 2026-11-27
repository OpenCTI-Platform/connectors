---
name: connector-manager-supported-migration
description: >-
  Migrate a legacy OpenCTI connector to manager-supported mode without
  restructuring it: Pydantic settings on connectors-sdk, wired into the existing
  code, manifest flag, generated config schema and tests, one commit per step.
  Use when asked to migrate a connector to manager-supported or catalog mode, to
  replace get_config_variable or config.yml loading with ConnectorSettings /
  BaseConnectorSettings, or to migrate several connectors in parallel. Input: a
  connector path (e.g. "external-import/vxvault") and the GitHub issue number.
  Not for building a new connector or for the full verified rework (package
  restructuring, schedule_iso, logging, STIX IDs).
---

# Manager-supported migration

Migrates one legacy OpenCTI connector to manager-supported mode: its
configuration is loaded and validated by Pydantic settings built on
`connectors_sdk.BaseConnectorSettings`, the pycti helper is built from
`settings.to_helper_config()`, and the connector ships a generated config
schema. The rest of the connector stays as it is.

The procedure itself is tool-neutral. Only the "Run modes" section (several
connectors in parallel, with subagents) needs a tool that can launch agents.

Paths below are relative to the repository root. `<path>` is the connector
directory (for example `external-import/vxvault`) and `<name>` its last
segment (`vxvault`), used as the commit scope.

**Working directory.** Run every command from the root of the working copy
you were given (the repository, or the workspace or worktree of Run modes).
The one `cd` is in the connector-linter command, which runs in a subshell, so
you are back at the root afterwards. Edit and commit only under `<path>`.

## Hard rules

- MUST have a connector path and a GitHub issue number. NEVER guess either.
- MUST commit after each of the 6 steps, before starting the next. NEVER batch steps.
- NEVER restructure, rename or move files or classes, convert the scheduling loop to
  `schedule_iso`, or refactor logging, converters or STIX IDs. Stop and report instead.
- NEVER delete an existing file. The only renames allowed are those of Step 1.
- NEVER invent or copy a UUID: generate it and check it is unique (Step 2).
- MUST unwrap every `SecretStr` with `.get_secret_value()` where it leaves the settings (Step 3).
- NEVER edit outside `<path>` or the working directory you were given. NEVER push, NEVER open a
  pull request.
- NEVER report success with fewer than 6 commits or a failing validation command.

## Inputs

- **Connector path** (required).
- **GitHub issue number** (required): every commit message ends with
  `(#<issue>)`. If it is missing, stop and ask for it. Never guess it. With
  several connectors, each has its own issue.
- **Working directory** (optional): when the caller runs several migrations
  in parallel, it gives each one its own jj workspace or git worktree. Do
  every read, edit, validation and commit inside that directory.

## Run modes

1. **One connector, no working directory given**: run the procedure below in
   the current working copy.
2. **A working directory is given**: `cd` into it first and work only there.
   Never create or remove workspaces or worktrees yourself and never launch
   agents. You may have no way to reach the user: return a question verbatim
   in your final report instead of asking it. Commits stay on the
   workspace's or worktree's branch after the caller removes it.
3. **Several connectors** (needs a tool that launches agents, such as Claude
   Code): you are the coordinator and do not run the steps yourself.
   1. Check each path against the stop conditions first, and make sure each
      has its own issue number. Ask about a flagged connector and do not start
      it until answered. The others proceed.
   2. One working directory per connector, from up-to-date trunk, named
      `ms-<slug>` (`external-import/vxvault` gives `ms-vxvault`):

      ```bash
      # jj repository (a `.jj/` directory exists at the root)
      jj git fetch
      jj workspace add -r 'trunk()' --name ms-<slug> ../ms-<slug>

      # git repository
      git worktree add -b ms-<slug> ../ms-<slug> origin/master
      ```

   3. Launch all workers in a single response, in the background, one agent
      per connector. Each prompt: "Run the `connector-manager-supported-migration`
      skill on connector `<path>`, GitHub issue `<issue>`. Work only in
      `<dir>`: `cd` into it first and do every edit, validation and commit
      there. Do not create or remove workspaces or worktrees, do not launch
      agents, do not push, do not open a pull request. You cannot reach the
      user: if the skill needs an answer, stop and return the question
      verbatim. One commit per step and the skill's final report format. User
      preferences: `<preferences or none>`."
   4. Wait for the completion notifications (do not poll), read each result
      and give a per-connector summary.
   5. Clean up a directory only when it was created in this run, its worker
      reported success and its commits are on the branch or bookmark. Use
      `jj workspace remove ms-<slug>` (jj) or `git worktree remove ../ms-<slug>`
      (git). Otherwise keep it and say why.

A plain question about migration ("what does manager-supported mean?") gets a
direct answer, without running the procedure.

## Scope

Change how configuration is loaded and read. Keep the code shape.

In scope:

1. Normalize the config files and requirements.
2. Add a `settings.py` that mirrors the existing variables.
3. Swap config loading for the settings in the existing code, in place.
4. Set `manager_supported` to `true` in the manifest.
5. Generate the config schema and its documentation.
6. Add tests for the settings and their wiring.

Out of scope (the broader "verified" work, done separately, see
`templates/<type>/` for the target layout):

- Restructuring into a `src/connector/` package, splitting files, adding an
  entry point, renaming files or classes, moving code.
- Replacing the scheduling loop with `schedule_iso` or an SDK base connector.
- Refactoring logging, converters or STIX ID generation.

If the connector needs any of this to work, stop and report it instead of
widening the change.

## Stop conditions

Stop, make no further edits and tell the user what was found. Ask when it is a
question, report when it is a failure.

- The path does not exist or has no `src/`.
- **Already migrated**: the manifest already has `"manager_supported": true`,
  or a `settings.py` already exists under `src/`. Say which signal was found
  (manifest, `settings.py` with its path, or both) and ask whether to continue.
  Never overwrite an existing `settings.py` silently.
- Wiring the settings would require moving code or splitting or renaming files
  or classes.
- **Pass-through config class**: after Step 3, the legacy config class or file
  (`ConfigLoader`, `config_loader.py`...) only builds `ConnectorSettings()` and
  copies its fields one by one. Ask whether to remove it, and never create a new
  one. If the user agrees, the entry point builds `ConnectorSettings()` and
  passes it to the helper and the connector, the connector reads
  `settings.<section>.<field>` directly, derived values move into the class that
  uses them, and the imports and test references to the removed class go away.
- Commit signing is configured but fails: report it, do not commit unsigned.
- `mise run gs`, flake8 or the tests still fail after two fix attempts: report
  the failing output.

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
6. The README configuration section.
7. Any existing `settings.py` under `src/`: apply the "Already migrated" stop.

Infer field types from the legacy calls:

```python
get_config_variable("ENV_VAR_NAME", ["section", "key"], config, isNumber, default, required)
```

- `isNumber=True` gives `int`.
- `default` gives the field default (`None` when absent).
- `required=True` gives a field with no default.
- `true`/`false` values give `bool`.
- Names containing `token`, `key`, `secret` or `password` give `SecretStr`.
- A value the code splits on commas (`.split(",")`, with or without `.strip()`)
  gives `ListFromString` from `connectors_sdk` with a list default
  (`default=["A", "B"]`). Remove the manual split in Step 3: the SDK type
  already splits and strips. Do not test the splitting in the connector.
- Everything else is `str`.

## Commits

One commit per step, made as soon as the step is done and before the next
one starts. Each commit is a reviewable unit, so never batch steps. Print
`Step N/6 done: <message>` after each one.

Before every commit, format the connector (versions pinned by CI in
`ci-requirements.txt`, see `AGENTS.md`):

```bash
uvx isort==7.0.0 --profile black --line-length 88 <path>
uvx black==26.10.1 <path>
```

Then commit with the repository's VCS:

- jj (a `.jj/` directory exists at the root): `jj commit -m "<message>"`
- git: `git add <path> && git commit -S -m "<message>"`

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
the person who ships the branch makes sure the commits are signed (jj signs
its own commits on push when configured to).

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
`BaseInternalImportFileConnectorConfig`. Always subclass it: never use the
SDK base config directly.

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

This is the only scheduling change of the migration. Converting the loop to
`schedule_iso` stays out of scope.

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
- The README configuration section is updated in Step 5, once the generated
  documentation exists.

### Make `ConnectorSettings` importable by the schema generator

The generator imports `from src import ConnectorSettings`, then
`from src.main import ConnectorSettings`. Many connectors need no
`src/__init__.py` because `src/main.py` already imports `ConnectorSettings` at
module level. Do not add one up front. When Step 5 fails with an import error
on `ConnectorSettings` (typical case: Step 3 builds the settings in a class
module, so `src/main.py` does not import them), add a minimal `src/__init__.py`
in the Step 5 commit, using the same import style as the connector's entry
point:

```python
from <pkg>.settings import ConnectorSettings  # or: from settings import ConnectorSettings

__all__ = ["ConnectorSettings"]
```

Do not add an unused `ConnectorSettings` import to `src/main.py` for the
generator: flake8 flags it (F401).

The generator tries `ConfigLoader` before `ConnectorSettings`. If an existing
`src/__init__.py` exports a legacy `ConfigLoader`, replace that export in this
step, otherwise the schema is built from the old config.

`settings.py` and, only when needed, `src/__init__.py` are the only new source
files of the migration.

Commit 2.

## Step 3: use the settings in the existing code

Edit the existing module in place, with the smallest change that swaps the
config source. Import the settings in the connector's own import style, for
example `from settings import ConnectorSettings`.

| Legacy code | Replacement |
|---|---|
| `yaml.load(open(config_file_path), ...)` and the path plumbing | Remove |
| `OpenCTIConnectorHelper(config)` | `self.config = ConnectorSettings()`, then `OpenCTIConnectorHelper(config=self.config.to_helper_config())` |
| `get_config_variable("<SECTION>_<KEY>", ...)` | `self.config.<section>.<key>` |
| `get_config_variable("CONNECTOR_<KEY>", ...)` | `self.config.connector.<key>` |
| A `SecretStr` value passed to a client, an auth header or a URL | `.get_secret_value()` (keep the `None` case of an optional secret) |
| A legacy interval read | `int(self.config.connector.duration_period.total_seconds())` (or the unit the loop expects) |
| `get_config_variable("CONNECTOR_UPDATE_EXISTING_DATA", ...)` | Remove the read: the SDK has no such field |
| `update=update_existing_data` in `send_stix2_bundle` | Remove the argument |

A secret read through `self.config.<section>.<key>` is a `SecretStr`. Unwrap
it at every place where it leaves the settings (client constructor,
`Authorization` header, query string). Mocked tests do not catch a missed one:
the client would send the masked value and the API answers 401.

- Build `ConnectorSettings()` where the config was loaded before (usually
  `__init__`, sometimes the `__main__` block).
- Keep `playbook_compatible=True` on the helper when it is already there:
  `OpenCTIConnectorHelper(config=self.config.to_helper_config(), playbook_compatible=True)`.
- Keep the scheduling loop, the logging calls, the class names and the
  `if __name__ == "__main__"` block.
- Read values from `self.config.<section>.<field>`, not from a legacy class
  that copies them. If that class ends up as a pass-through, apply the stop
  condition.
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

## Step 5: generate the config schema and update the README

```bash
mise run gs <path>
```

It writes `__metadata__/connector_config_schema.json` and
`__metadata__/CONNECTOR_CONFIG_DOC.md`. Never edit those by hand.

- It must exit 0. An `ImportError` on `ConnectorSettings` means the generator
  cannot find it: add the `src/__init__.py` re-export described in Step 2 (or
  fix the `ConfigLoader` export) and rerun.
- The task builds its own Python 3.12 environment and installs this
  checkout's `connectors-sdk`. That SDK pins an exact pycti. If the connector
  pins an older pycti, dependency resolution fails: report it rather than
  bumping pycti inside this migration (`AGENTS.md` says to rebase on the
  latest `master` first).
- Check the result: `required` lists `OPENCTI_URL`, `OPENCTI_TOKEN` and the
  connector's required variables, and every setting has a property.

Then replace the README configuration section (usually "Configuration") with a
link to the generated document, as in `templates/<type>/README.md`:

```markdown
Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)
```

- Delete the parameter tables of that section: the generated document lists
  every variable. Keep the other sections and any prose that is not a table.
- If `CONNECTOR_MAX_TLP` appears in the generated schema and `grep -rn max_tlp
  <path>/src` finds no read of it, add under the link: `> **Note:**
  CONNECTOR_MAX_TLP is listed there, but the connector does not check it yet.`

Commit 5, with the README and any `src/__init__.py`.

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

Define `MINIMAL_VALID_SETTINGS_DICT`: OpenCTI URL and token, the `connector`
fields the type requires (`live_stream_id` for a stream; none for the other
types), and the required custom fields only. Cover:

1. `test_settings_should_accept_valid_input`, parametrized with every field
   set, and with `MINIMAL_VALID_SETTINGS_DICT`.
2. `test_settings_should_apply_defaults`: the minimal dict yields the
   documented defaults (name, scope, custom fields, and `duration_period`
   for an external-import connector).
3. `test_settings_should_default_connector_id`: the minimal dict with only
   `connector.id` omitted gives `settings.connector.id` equal to the UUID from
   `settings.py`, and `UUID(settings.connector.id).version == 4`. Keep the other
   required `connector` fields (`live_stream_id` for a stream).
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
(cd shared/tools/connector_linter && uv run connector-linter check ../../../<path>)
python3 .github/scripts/deptry_scan.py <path>
bash run_test.sh ./<path>/tests/test-requirements.txt
```

- `run_test.sh` blocks network access, installs the local `connectors-sdk` and
  needs git and an `origin/master` ref. In a jj workspace with no `.git`,
  or when it skips the connector for lack of changes since the merge base, use
  a throwaway environment instead (it does not block the network, so mock every
  call):

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

Before reporting, list the commits (`jj log` or `git log --show-signature`) and
confirm the six migration commits exist. If fewer, say so and do not report
success. With several connectors, give one block per connector.

| Step | Commit | Status |
|---|---|---|
| 1. Config files | `<id>` | done / skipped (why) |
| ... | | |

Then:

- Test count and the result of each validation command.
- The generated `connector.id` UUID.
- Whether a `src/__init__.py` re-export was needed, and why.
- Files left unused by the migration (kept on purpose).
- Follow-up candidates spotted but not done: variables with a wrong or
  copied prefix (`CONNECTOR_TEMPLATE_*`), connector-linter findings, verified
  work (restructuring, `schedule_iso`, logging, STIX IDs).

Done when: the six commits exist with the messages above, each ending with the
issue reference; `ConnectorSettings` has a connector-specific config with a
unique UUIDv4 `id` default; `mise run gs` exits 0; flake8, connector-linter,
deptry and the tests pass; the manifest says `manager_supported: true`; no file
was deleted, split or renamed beyond Step 1 and an approved pass-through
config class.

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

## Reminders

One commit per step, each ending with `(#<issue>)`. Structure-preserving only. Mirror the existing
variables, handle `duration_period` as in Step 2, unwrap secrets, never overwrite an existing
`settings.py`, never push. Stop and ask on every stop condition.
