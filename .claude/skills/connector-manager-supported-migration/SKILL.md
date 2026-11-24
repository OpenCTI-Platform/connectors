---
name: connector-manager-supported-migration
description: >-
  Minimal, structure-preserving migration of an OpenCTI connector to
  manager-supported mode. Invoke this skill when the user asks for a "lite",
  "light", "minimal", or "structure-preserving" manager-supported migration, or
  when they want ONLY Pydantic settings + their usage (config normalization,
  settings creation, wiring settings into the existing code, manifest metadata,
  config-schema generation, test scaffolding, formatting/validation) while
  keeping the current file structure, file names, class names, and scheduling
  unchanged. Adds Pydantic settings and wires them into the EXISTING code in
  place; each step produces one commit. It does NOT do any broader rework
  (package restructuring, connector.py/main.py split, schedule_iso conversion,
  logging refactor, STIX-ID fixes). Input: one or more connector paths (e.g.
  "external-import/vxvault") and the GitHub issue number of each.
---

# Manager-Supported Migration

You perform a **minimal, structure-preserving** migration of OpenCTI connectors to
**manager-supported** mode. You run the procedure below yourself, in this session. You add Pydantic
settings and make the existing code consume them, nothing more.

Guiding principle: **keep the existing file structure and code shape; change only how configuration
is loaded and read.**

It does **none** of the broader work: no restructuring, no file splitting, no `schedule_iso`
conversion, no logging refactor, no STIX-ID determinism fixes.

**Starting state**: legacy connector (`get_config_variable` / yaml config), `manager_supported` not
true in the manifest, no `settings.py`.
**Target state**: 6-7 commits; config flows through validated Pydantic settings and
`to_helper_config()`; source layout unchanged; `manager_supported: true`; schema generated; flake8
and pytest passing.
**Progress line**: after each commit print `✅ Step N/7: <commit message>`.

## Hard rules

- MUST have a connector path and a GitHub issue number. If the user gave none, ask for it. NEVER guess
  either, and NEVER invent an issue number.
- MUST commit after EACH of the 7 steps, before starting the next (see Execution model). NEVER batch.
  Step 7 commits only if formatting changed files.
- MUST do only what this file describes. For any other action, stop and ask the user first (see Stop
  conditions).
- NEVER restructure into a `src/connector/` package, never split code into
  `connector.py` / `main.py` / `__init__.py`, never create a new entry point, never rename or move
  files, never rename classes, never move code between files.
- NEVER convert scheduling to `schedule_iso` / `duration_period` (keep the existing loop), never
  refactor logging (`log_info` to `connector_logger`), converters or STIX-ID generation.
- NEVER delete, rename, move or split existing files. The only renames allowed are those of Step 1
  (`docker-compose.yaml` to `.yml`, `config.yaml.sample` to `.yml.sample`). The only deletion allowed
  is a pass-through config file the user explicitly approved removing (see Stop conditions).
- NEVER edit files outside the connector directory (or the assigned worktree). NEVER push, never
  open a PR.
- NEVER invent a UUID: generate it as in Step 2.
- MUST sign every commit (`git commit -S`): CI rejects unsigned commits.
- With more than one connector, NEVER run the steps in the shared working copy: one `git` worktree
  per connector (see Run modes).

The only new code files you may add: `settings.py` (Step 2) and, only when Step 5 proves
`ConnectorSettings` is not importable by the schema generator, a minimal `src/__init__.py` re-export
(see Step 5).

## Stop conditions

Stop, make no further edits, and tell the user what was found. Ask before continuing when it is a
question, report when it is a failure:

- The path does not exist or has no `src/`.
- **Already migrated signal**: the manifest `__metadata__/connector_manifest.json` already has
  `"manager_supported": true` **OR** a `settings.py` already exists under `src/`. Say which signal was
  found (manifest, `settings.py` with its path, or both) and ask whether to continue. Never overwrite
  an existing `settings.py` silently.
- Wiring the settings would require moving code, splitting or renaming files or classes. That is the
  full migration: do not expand scope.
- **Pass-through config class**: after Step 3, the legacy config class or file (`ConfigLoader`,
  `ConfigConnector`, `config_loader.py`...) only builds `ConnectorSettings()` and copies its fields
  one by one. Ask whether to remove it. Never create a new one. If the user says yes: the entry point
  builds `ConnectorSettings()` and passes it to the helper and to the connector, the connector reads
  `settings.<section>.<field>` directly, values derived from several fields (e.g. an `impact_map`) move
  into the class that uses them, and the imports and test references to the removed class go away.
- Commit signing is not configured (`git commit -S` fails): report it, do not commit unsigned.
- `mise gs`, flake8 or pytest still fails after two fix attempts: report the failing output.
- Any action not described in this file is needed.

Questions go to the user directly. When you run as a subagent with no way to reach the user (see Run
modes), return the question verbatim in your final report instead.

## Input and run modes

Input: a connector path relative to the repo root (e.g., `external-import/vxvault`) and its GitHub
issue number, taken from the user's request or the skill arguments, plus optional user preferences
(e.g., "don't generate config schema", "skip the venv import check"). A preference may skip a check
or a generation; say so in the report and adjust the expected commit count. It never lifts a hard
rule.

Pick the mode:

1. **One connector, no worktree given**: run Pre-flight and Steps 1-7 yourself in the current
   working copy.
2. **A worktree directory is given** (e.g., `../ms-vxvault`, passed by a coordinator or another
   skill): `cd` into it first and do ALL reads, edits, validation and `git commit`s inside it, never
   in the shared working copy. Never create or remove worktrees yourself, never launch agents. You
   may have no way to reach the user: return questions in your final report. Commits stay on the
   worktree's branch after the coordinator removes the worktree.
3. **More than one connector path**: you are the coordinator. Do not run the steps yourself.
   1. Check each path against the stop conditions first (path, manifest, `settings.py`) and make sure
      each one has its own issue number. Ask about any flagged connector and do not start it until
      answered; the others proceed.
   2. One worktree and one branch per connector, from up-to-date `master`. Derive a slug from the path
      (e.g. `external-import/vxvault` to `ms-vxvault`):
      ```bash
      git worktree add -b ms-<slug> ../ms-<slug> origin/master
      ```
      Each worktree has its own working copy but shares the repo, so commits land in the same repo
      and different connectors never conflict.
   3. Launch ALL workers in a single response, in the background, one `Agent` call per connector with
      `subagent_type: "general-purpose"`. Each prompt: "Run the `connector-manager-supported-migration`
      skill with the Skill tool on connector `<path>`, GitHub issue `<issue>`. Work ONLY in the git
      worktree `<dir>`: `cd` into it first and do all edits, validation and `git commit -S`s there. Do
      not create or remove worktrees, do not launch agents, do not push, do not open a PR. You cannot
      reach the user: if the skill needs an answer, stop and return the question verbatim. Follow the
      skill's hard rules, one commit per step, and its final report format. User preferences:
      `<preferences or none>`."
   4. Wait for the completion notifications (do not poll), read each result and report a
      per-connector summary.
   5. **Clean up a worktree** only when it was created in this run, its worker reported success and
      its commits appear in `git log ms-<slug>`:
      ```bash
      git worktree remove ../ms-<slug>
      ```
      The branch `ms-<slug>` keeps the commits. Otherwise keep the worktree and tell the user why.

If the user only asks a simple question about migration (e.g., "what does manager supported mean?"),
answer directly without running the procedure.

## Pre-flight: gather context

Before any change, read and analyze:

1. **Source files** in `src/`: locate the module that builds `OpenCTIConnectorHelper` and calls
   `get_config_variable(...)` / loads `config.yml`. This is where you wire the settings.
   **Note the existing layout: you must preserve it.**
2. **docker-compose.yml**: extract ALL environment variables; custom ones (not `OPENCTI_*`/`CONNECTOR_*`)
   share a prefix (e.g., `VXVAULT_*`) that becomes the Pydantic config section name
3. **config.yml.sample** (if exists): cross-reference config vars, types, defaults
4. **.env.sample** (if exists): additional config reference
5. **`__metadata__/connector_manifest.json`**: check `manager_supported` status and connector type
6. **Existing `settings.py`** anywhere under `src/`: apply the already-migrated stop condition
7. **Connector type**, determined by parent directory:
   `external-import`, `internal-enrichment`, `stream`, `internal-export-file`, `internal-import-file`

### How to extract the config section name

From docker-compose.yml environment vars, collect custom vars (not `OPENCTI_*`/`CONNECTOR_*`):

```
VXVAULT_URL=...        →  prefix = "VXVAULT_"
VXVAULT_INTERVAL=...
VXVAULT_SSL_VERIFY=...
```

Config section name = prefix lowercased without trailing underscore = `vxvault`.

### How to infer field types from `get_config_variable`

```python
get_config_variable("ENV_VAR_NAME", ["section", "key"], config, isNumber, default, required)
#                    ^1st arg         ^2nd arg             ^3rd   ^4th     ^5th     ^6th
```

- 4th arg `True` → field type is `int`
- 5th arg is the default value; `None` by default
- 6th arg `True` → field is required (no default in Pydantic)
- If env var name contains `token`, `key`, `secret`, `password` → use `SecretStr`
- Boolean values (`True`/`False`/`true`/`false` in docker-compose) → `bool`
- Everything else → `str`

### Comma-separated list values → `ListFromString`

If the existing code does `.split(",")` (with or without `.strip()`) on a config value, type the field
`ListFromString` (imported from `connectors_sdk`) with a **list** default (`default=["A", "B"]`),
never `str`. `ListFromString` already splits on commas and strips the spaces, so remove the manual
split from the code. Step 5 regenerates the schema, where the default becomes an array. Do not add a
connector test for the splitting itself: `ListFromString` is tested once in the SDK
(`connectors-sdk/tests/test_settings/test_annotated_types.py`), not in each connector.

## Execution model: commit after every step

The migration is 7 sequential steps. The commit IS the completion of the step: after finishing the
edits for step N, commit IMMEDIATELY, print the progress line, then start step N+1. Never "come back
to commit later".

Commit with a signed commit (CI rejects unsigned ones):

```bash
git add -A -- <connector path> && git commit -S -m "<message>"
```

Every message ends with the GitHub issue reference `(#<issue>)`, as required by the repository's
Conventional Commits convention (`type(scope): description (#issue)`):

```
Step 1 → feat(<name>): normalize config files for manager-supported migration (#<issue>)
Step 2 → feat(<name>): add Pydantic settings for manager-supported mode (#<issue>)
Step 3 → feat(<name>): use Pydantic settings in existing connector code (#<issue>)
Step 4 → feat(<name>): set manager_supported to true in connector manifest (#<issue>)
Step 5 → feat(<name>): generate connector config schema for manager-supported mode (#<issue>)
Step 6 → feat(<name>): add unit tests for manager-supported mode (#<issue>)
Step 7 → style(<name>): apply isort and black formatting (#<issue>)
```

---

## Step 1: Normalize config files

### docker-compose.yml

- Rename `docker-compose.yaml` → `docker-compose.yml` if needed
- Uncomment `#- VAR=...` entries into valid YAML list items
- Remove any `CONNECTOR_TYPE=...` line (SDK handles this now)
- Normalize booleans: `False` → `false`, `True` → `true`

### config.yml.sample (if exists)

- Rename `config.yaml.sample` → `config.yml.sample` if needed
- Uncomment `#key: value` lines used as real config keys

### .env.sample

- If missing (and no config.yml.sample exists), create from docker-compose env vars

### src/requirements.txt: append if missing

```
pydantic >=2.8.2, <3
connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk
```

**→ Checkpoint: commit with the Step 1 message, then Step 2.**

---

## Step 2: Add settings.py (mirror the existing config)

Create a `settings.py` **next to the existing module that loads the config** (e.g., if the entry
point is `src/main.py`, create `src/settings.py`; if the connector already has a package like
`src/mypkg/`, put it in `src/mypkg/settings.py`). **Do NOT create a new `connector/` package or
restructure anything.**

Mirror the connector's **existing** config variables 1:1 into Pydantic. Do NOT introduce new config
concepts (no `duration_period` migration, no `DeprecatedField`): keep the connector's own fields,
including its existing `interval`/`polling` field, exactly as they are today.

### Pattern by connector type

Use the SDK base config for the standard `opencti`/`connector` sections; keep the connector's own
variables in a custom section.

**EXTERNAL_IMPORT** (custom config section):

```python
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class <ConnectorName>Config(BaseConfigModel):
    """Config fields specific to this connector (mirror of the existing variables)."""
    url: str = Field(description="...", default="...")
    api_key: SecretStr = Field(description="...")          # no default = required
    ssl_verify: bool = Field(description="...", default=True)
    interval: int = Field(description="...", default=60)   # keep the existing scheduling field
```

**INTERNAL_ENRICHMENT:** Use `BaseInternalEnrichmentConnectorConfig`.
**STREAM:** Use `BaseStreamConnectorConfig`.
**INTERNAL_EXPORT_FILE:** Use `BaseInternalExportFileConnectorConfig`.
**INTERNAL_IMPORT_FILE:** Use `BaseInternalImportFileConnectorConfig`.

### MANDATORY: subclass the connector config and give `id` a unique UUIDv4 default

Never use the SDK base connector config directly. Always declare a connector-specific subclass that
overrides `id`, `name` and `scope` with this connector's own defaults, and use it in `ConnectorSettings`:

```python
class <ConnectorName>ConnectorConfig(BaseExternalImportConnectorConfig):  # or the type-matching base
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="<FRESH-UNIQUE-UUIDV4>",
    )
    name: str = Field(
        description="The name of the connector.",
        default="<ConnectorName>",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["<scope>"],
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: <ConnectorName>ConnectorConfig = Field(
        default_factory=<ConnectorName>ConnectorConfig
    )
    <section>: <ConnectorName>Config = Field(default_factory=<ConnectorName>Config)
```

Why: `_BaseConnectorConfig.id` in the SDK (`connectors-sdk/connectors_sdk/settings/base_settings.py`)
is **required with no default**. Without the override, `CONNECTOR_ID` stays mandatory and the
connector cannot be deployed from the catalog without manual input. 80+ connectors already follow
this convention and no linter enforces it, so check it explicitly.

Rules for the UUID:

1. **Generate a fresh UUIDv4**: never copy one from another connector, never invent one by hand, never
   use a pattern-looking placeholder (`00000000-...`, `aaaaaaaa-bbbb-...`).

   ```bash
   python3 -c "import uuid; print(uuid.uuid4())"
   ```

2. **Verify it is unique across the repo before committing:**

   ```bash
   grep -rI "<the-uuid>" --include='*.py' . | grep -v '/.venv/'   # MUST return nothing
   ```

3. If the connector **already** declares an `id` default, keep it, but still confirm it is unique
   repo-wide (duplicates exist, e.g. the two `team-cymru-scout*` connectors).

Two things this does **not** change; do not "fix" them:

- **Generated config schema is unaffected.** `ConnectorConfigJsonSchemaGenerator.filter_schema`
  always removes `CONNECTOR_ID`, so adding a default needs no regeneration.
- **`docker-compose.yml` / `config.yml.sample` keep `CONNECTOR_ID=ChangeMe`.** Linter check VC104
  accepts `ChangeMe` (and `${ENV_REF}`). A real UUID committed as a deployment value would give every
  deployment the same identity in OpenCTI.

### Update config files to match the settings

- Ensure the vars exist in `docker-compose.yml`, and in `config.yml.sample` / `.env.sample` if present
- Settings **with** default values → present but **commented out** (defaults in settings.py are the
  source of truth)
- Settings **without** default values (required) → present, **uncommented**, value `ChangeMe`

### Legacy `ConfigLoader` export

The config-schema generator tries `ConfigLoader` first (`from src import ConfigLoader`, then
`from src.main import ConfigLoader`), and only then `ConnectorSettings`. If an **existing**
`src/__init__.py` exports a legacy `ConfigLoader`, **replace** that export with `ConnectorSettings`
(mirror the connector's own import style); otherwise the schema would be built from the OLD config.
Do NOT create a `src/__init__.py` here: whether one is needed is decided in Step 5.

**→ Checkpoint: commit with the Step 2 message, then Step 3.**

---

## Step 3: Use the settings in the existing code (in place)

Edit the **existing** module(s) in place. Make the smallest change that swaps configuration loading
to the Pydantic settings. Do not move code, split files, rename the class, or change the scheduling
loop or logging.

Import the settings using the existing import style, e.g. `from settings import ConnectorSettings`.

### Replacement rules

| Legacy code | Replacement |
|---|---|
| `config = yaml.load(open(config_file_path), ...)` (and the file-path plumbing) | Remove; not needed anymore |
| `self.helper = OpenCTIConnectorHelper(config)` | `self.config = ConnectorSettings()` then `self.helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())` |
| `get_config_variable("VAR", ["section", "key"], config, ...)` | `self.config.<section>.<field>` |
| `get_config_variable("CONNECTOR_*", ...)` (standard vars) | read from `self.config.connector.<field>` |

For **internal-enrichment**, if the helper is built with `playbook_compatible=True`, preserve that:
`OpenCTIConnectorHelper(config=self.config.to_helper_config(), playbook_compatible=True)`.

### Rules

- **Instantiate `ConnectorSettings()` where the config was previously loaded** (usually the class
  `__init__`, or the `__main__` block if that's where the helper is built): mirror the existing flow.
- **Keep the existing scheduling** (`while True` + `time.sleep(self.interval)` stays; do NOT convert
  to `schedule_iso`). Read the interval from `self.config.<section>.interval`.
- **Do not touch logging calls, converters, STIX-ID generation, or method bodies** beyond swapping
  the config source.
- **Keep the `if __name__ == "__main__"` block** and the class name intact.
- **Read values from `self.config.<section>.<field>`**, not from a legacy config class that copies
  them. If that class ends up as a pass-through, apply the "Pass-through config class" stop condition.

**→ Checkpoint: commit with the Step 3 message, then Step 4.**

---

## Step 4: Update the connector manifest

In `__metadata__/connector_manifest.json`, set:

```json
"manager_supported": true
```

Do NOT modify any other fields.

**→ Checkpoint: commit with the Step 4 message, then Step 5.**

---

## Step 5: Generate the manager-supported config schema

The connector manager consumes a generated env-var **config schema**. Generating it also proves that
`ConnectorSettings` is wired correctly: a broken import here means the connector is **not actually
manager-supported**, so this step MUST pass.

### Generate

Run the repo's generator (it builds a temp venv, imports `ConnectorSettings`, and writes
`__metadata__/connector_config_schema.json` + `__metadata__/CONNECTOR_CONFIG_DOC.md`):

```bash
mise run generate_config_schema .     # alias: mise gs .
```

- It MUST exit 0 with no `ImportError` / `ModuleNotFoundError` for `ConnectorSettings`.
- The SDK pins an exact `pycti` version (see `connectors-sdk/pyproject.toml`). If the connector's
  `src/requirements.txt` pins an older `pycti`, dependency resolution fails and generation stops.
  Set the connector's `pycti` pin to the SDK's version (a one-line change to `src/requirements.txt`,
  committed with Step 5 and mentioned in the report). If the connector has other pins that conflict,
  stop and report instead of guessing.
- If the connector pins `stix-shifter` / `antlr4` (some stream connectors), the default Python 3.13
  venv fails on the removed `typing.io`; run it with Python 3.11:
  `UV_PYTHON=3.11 mise run generate_config_schema .`

### Exposing `ConnectorSettings` to the generator (only when needed)

The generator imports the model with `from src import ConnectorSettings`, then falls back to
`from src.main import ConnectorSettings`. **Do not add a `src/__init__.py` up front**: this migration does not
add files unnecessarily, and most already-migrated connectors have none (about two thirds of the
manager-supported connectors in the monorepo have no `src/__init__.py` and rely on their entry point
`src/main.py` importing `ConnectorSettings` at module level).

Run the generator first. Add the minimal re-export **only if** it fails with a `ConnectorSettings`
import error (typical case: Step 3 instantiated the settings in a class module, so `src/main.py` does
not import `ConnectorSettings`, and `src` has no export). Mirror the entry point's own import style:

```python
# src/__init__.py: flat layout (settings at src/settings.py)
from settings import ConnectorSettings

__all__ = ["ConnectorSettings"]
```

```python
# src/__init__.py: package layout (settings at src/<pkg>/settings.py)
from <pkg>.settings import ConnectorSettings

__all__ = ["ConnectorSettings"]
```

Re-run until it exits 0. A new `src/__init__.py` goes into the Step 5 commit. Do not add an unused
`ConnectorSettings` import to `src/main.py` just for the generator (flake8 F401): use the re-export.
Also make sure no legacy `ConfigLoader` remains importable from `src` or `src.main`.

### Update the README configuration section

Once `CONNECTOR_CONFIG_DOC.md` exists, the README section that documents the configuration (usually
"Configuration") is replaced by a link to it, as in the connector templates:

```markdown
Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)
```

- Delete the parameter tables of that section (Generic Parameters, connector-specific parameters,
  etc.): the generated doc lists every variable. Keep the other sections and any prose that is not a
  variable table.
- If `CONNECTOR_MAX_TLP` appears in the generated schema and `grep -rn max_tlp src/` finds no read of
  it in the connector code, add this note under the link: `> **Note:** CONNECTOR_MAX_TLP is listed
  there, but the connector does not check it yet.`
- The README change goes into the Step 5 commit.

### Sanity check the output

`required` lists the connector's mandatory env vars (e.g. `OPENCTI_URL`, `OPENCTI_TOKEN`, plus
your required custom vars) and the property count matches your settings.

**→ Checkpoint: commit with the Step 5 message, then Step 6.**

---

## Step 6: Create test files

### tests/test-requirements.txt

```
-r ../src/requirements.txt
pytest==8.4.2
```

### tests/conftest.py

```python
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
```

### tests/test_main.py

Create with three tests using a `StubConnectorSettings` that overrides `_load_config_dict`:

1. `test_connector_settings_is_instantiated`: verify `to_helper_config()` returns dict
2. `test_opencti_connector_helper_is_instantiated`: verify helper attributes from config
3. `test_connector_is_instantiated`: verify the existing connector class instantiates with the stubbed
   settings (patch `ConnectorSettings` where the class imports it; use the helper fixture below)

The stub config dict MUST match the fields in settings.py. Use realistic values from docker-compose.yml.
Use the connector's existing fields, including `interval`. Do NOT add `duration_period` (the existing
scheduling is kept) and do NOT add a deprecated-interval migration test (there is no `DeprecatedField`).

Mock these in the `mock_opencti_connector_helper` fixture:

```python
module_import_path = "pycti.connector.opencti_connector_helper"
monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())
```

### tests/tests_connector/test_settings.py

Create with two parametrized test functions:

1. `test_settings_should_accept_valid_input` with:
   - `full_valid_settings_dict`: ALL fields (required + optional)
   - `minimal_valid_settings_dict`: only required fields, connector section empty `{}`

2. `test_settings_should_raise_when_invalid_input` with:
   - `empty_settings_dict`: `{}`
   - `missing_opencti_token`: opencti without token
   - `invalid_connector_id`: connector.id as int instead of str

Both use `FakeConnectorSettings` subclass that overrides `_load_config_dict`.
Invalid cases assert `ConfigValidationError` with message containing `"Error validating configuration"`.

3. `test_settings_should_default_connector_id`: MANDATORY, guards the Step 2 `id` override.
   Pass a config dict whose `connector` section is empty (`{}`), plus any sibling field the connector
   genuinely requires (e.g. `live_stream_id` for STREAM), and assert both the exact default and that
   it is a real UUIDv4:

```python
from uuid import UUID

def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.id == "<THE-UUID-FROM-SETTINGS-PY>"
    assert UUID(settings.connector.id).version == 4
```

**→ Checkpoint: commit with the Step 6 message, then Step 7.**

---

## Step 7: Format and validate

### Format

Run from the repository root, with the versions CI pins (`ci-requirements.txt`, also in `AGENTS.md`),
isort first and black second. A different local version can format differently and fail the CI check:

```bash
uvx isort==7.0.0 --profile black --line-length 88 <connector path>
uvx black==26.10.1 <connector path>
```

### Lint

From the repository root:

```bash
uvx flake8 --ignore=E,W <connector path>
```

### Test

From the connector directory:

```bash
# Create temp venv, install deps, run pytest
python3.12 -m venv /tmp/<connector>_test_venv
source /tmp/<connector>_test_venv/bin/activate
pip install -q -r tests/test-requirements.txt
python -m pytest tests/ -v
deactivate && rm -rf /tmp/<connector>_test_venv
```

### Import sanity check

Validate that the settings module imports and the existing entry module still imports cleanly, in a
temp venv so connectors-sdk and the connector's deps are available:

```bash
python3.12 -m venv /tmp/<connector>_migration_venv
source /tmp/<connector>_migration_venv/bin/activate
pip install -q -r src/requirements.txt
python -c "import sys; sys.path.insert(0, 'src'); from settings import ConnectorSettings; print('settings OK')"
deactivate && rm -rf /tmp/<connector>_migration_venv
```

Adjust the import path to the actual location of `settings.py`.

### Connector id uniqueness check

Confirm the UUIDv4 default declared for `connector.id` in Step 2 exists nowhere else in the repo:

```bash
grep -rI "<the-uuid>" --include='*.py' . | grep -v '/.venv/'   # MUST return only this connector's settings.py
```

If it returns any other connector, generate a new UUIDv4 and update both `settings.py` and the
`test_settings_should_default_connector_id` assertion.

If lint, tests or the import check fail, fix and re-run BEFORE committing. After two failed fix
attempts, stop and report the failing output (see Stop conditions).

**→ Checkpoint: commit with the Step 7 message ONLY if formatting changed files (check with `git diff` first). Otherwise skip the commit and say so.**

---

## Reporting

Before reporting, run `git log --oneline -n 10 --show-signature` and confirm 6-7 signed migration
commits exist. If fewer, say so explicitly and do not report success. In a batch, give one
block per connector.

Final report, under 40 lines per connector:

| Step | Commit | Status |
|------|--------|--------|
| 1. Config normalization | `<hash>` | ✅ |
| 2. Pydantic settings | `<hash>` | ✅ |
| 3. Settings wired into existing code | `<hash>` | ✅ |
| 4. Manifest metadata | `<hash>` | ✅ |
| 5. Config schema generation | `<hash>` | ✅ |
| 6. Unit tests | `<hash>` | ✅ |
| 7. Format & validate | `<hash>` | ✅ or skipped (no formatting changes) |

Also report:

- Manager-supported: config now flows through validated Pydantic settings; **file structure unchanged**.
- Whether a `src/__init__.py` re-export was needed (Step 5) and why.
- Not "verified": no restructuring, no scheduling/logging modernization, no converter/STIX-ID cleanup.
  Point the user to the right follow-up (see Out of scope).
- Test count passing, flake8 result, any manual follow-up needed, and any user preference that skipped
  a step.

**Done when**, all true: the 6-7 commits exist with the messages above; `ConnectorSettings` has a
connector-specific config with a unique UUIDv4 `id` default; `mise gs` exits 0; flake8 and pytest pass;
the manifest says `manager_supported: true`; no file was deleted, split or renamed beyond Step 1 and a pass-through config file the user approved removing.

## Out of scope

- Restructuring into a `src/connector/` package (`settings.py`, `connector.py`, `__init__.py`), adding
  `src/main.py`, injecting `config` and `helper` into the connector class, converting scheduling to
  `schedule_iso` with `duration_period` (and a `DeprecatedField` for the old interval), and moving
  logging to `connector_logger`. The reference layout is `templates/<type>/`. Do it as a separate,
  explicitly requested change.
- The broader "Verified" criteria (for example STIX-ID determinism or converter cleanup). The
  connector-linter command in `AGENTS.md` ("Validation commands") checks them.
- If wiring the settings needs that restructuring, stop (see Stop conditions). Never silently expand
  scope.

## Common pitfalls

- **Stay minimal**: if you catch yourself creating a `connector/` package, splitting files, renaming
  classes, converting to `schedule_iso`, or refactoring logging, STOP. That is the full migration.
- **Mirror config 1:1**: no new config concepts; keep the existing `interval` field and scheduling.
- **Build the helper from `to_helper_config()`**: this is what makes it manager-supported.
- **Import ordering**: third-party imports before local (isort handles this).
- **Commit granularity**: one commit per step (6-7 total; Step 7 commits only if formatting changed
  files). Fewer than 6 means a step was batched: split it. Every commit is signed and ends with
  `(#<issue>)`.
- **Schema generation must pass**: add the `src/__init__.py` re-export only when the generator cannot
  import `ConnectorSettings`, and replace any legacy `ConfigLoader` export. Use `UV_PYTHON=3.11` for
  `stix-shifter`/`antlr4` connectors.
- **Never leave `connector.id` without a default**: freshly generated, repo-unique UUIDv4 (Step 2).
  It is the most frequently forgotten part of this migration. Keep `CONNECTOR_ID=ChangeMe` in the
  config files regardless.
- **Do not overwrite earlier work**: an existing `settings.py` or `manager_supported: true` is a stop
  signal, not something to redo.

## Reminders (restated)

One commit per step, signed, ending with `(#<issue>)`, printed as `✅ Step N/7`. Structure-preserving
only: no restructuring, renames, `schedule_iso` or logging refactor. Never delete existing files. Never
invent a UUID or an issue number. One git worktree per connector in a batch. Stop and ask when the manifest already says `manager_supported: true` or a
`settings.py` already exists (name the signal), and on every other listed stop condition.
