# OpenCTI Connector Verified Linter

A flake8-style linter that validates whether an OpenCTI connector meets the **Verified** status criteria. Each check has a unique error code (e.g. `VC101`) and provides actionable suggestions for fixing violations.

## Installation

The linter is managed with [uv](https://docs.astral.sh/uv/) and lives in `shared/connector_linter/`.

```bash
# From the connector_linter directory
cd shared/connector_linter

# Install with uv (recommended)
uv sync

# Or install with pip
pip install -e .
```

## Usage

### Check a connector

```bash
# Basic check (all rules)
connector-linter check ../../external-import/mandiant

# Or run via uv
uv run connector-linter check ../../external-import/mandiant
```

### Output formats

```bash
# Colored terminal output (default — paths relative to CLI argument)
connector-linter check ./connector --format text

# Markdown output (for Notion / GitHub wikis / issue bodies)
connector-linter check ./connector --format markdown

# JSON output (for CI pipelines — always uses absolute paths)
connector-linter check ./connector --format json

# GitHub Actions annotations (paths relative to repo root)
connector-linter check ./connector --format github
```

### Rules documentation

```bash
# Print rules reference as Markdown to stdout
connector-linter docs

# Write to a file (for Notion import)
connector-linter docs -o rules.md
```

### Filtering checks

```bash
# Check a single file (connector root is resolved automatically)
connector-linter check ./connector/src/main.py
connector-linter check ./connector/docker-compose.yml

# Run only specific checks
connector-linter check ./connector --select VC101 --select VC102

# Run an entire category (prefix matching)
connector-linter check ./connector --select VC1xx   # all configuration checks
connector-linter check ./connector --select VC3xx   # all code checks
connector-linter check ./connector --select VC5xx   # all deprecation checks

# Ignore specific checks
connector-linter check ./connector --ignore VC306 --ignore VC307

# Show all checks including passed (default hides passed)
connector-linter check ./connector --verbose

# Filter by severity level
connector-linter check ./connector --severity warning  # show warnings and errors
connector-linter check ./connector --severity error     # errors only

# Use absolute paths in text output (JSON always uses absolute paths)
connector-linter check ./connector --abspath
```

### Project-level configuration (`pyproject.toml`)

Configure the linter at project level via `[tool.connector-linter]` in `pyproject.toml`. The file is auto-discovered by walking up from the connector directory (like Ruff).

```toml
[tool.connector-linter]
# Only run these checks/prefixes (same as --select)
select = ["VC1xx", "VC3xx"]

# Skip these checks (same as --ignore, merged with CLI --ignore)
ignore = ["VC306", "VC307"]

# Skip specific checks for files matching a glob pattern
[tool.connector-linter.per-file-ignores]
"tests/*.py" = ["VC309", "VC313"]
"src/main.py" = ["VC308"]
```

**Precedence rules** (inspired by Ruff):
- CLI `--select` overrides `select` from pyproject.toml
- CLI `--ignore` is merged with `ignore` from pyproject.toml (union of both)
- `per-file-ignores` applies after check execution and before inline `# noqa`
- Use `--config path/to/pyproject.toml` to specify an explicit config file

### Inline suppression (`# noqa`)

Suppress specific checks on individual lines using `# noqa` comments — same syntax as flake8:

```python
# Suppress all checks on this line
self.helper.log_info(msg)  # noqa

# Suppress a specific check
self.helper.log_info(msg)  # noqa: VC503

# Suppress multiple checks
confidence=80,  # noqa: VC504, VC302
```

Works in any file that uses `#` for comments (Python, YAML, Dockerfile, `.env`).

To ignore all `# noqa` directives (useful for CI audits):

```bash
connector-linter check ./connector --disable-noqa
```

### List all checks

```bash
connector-linter list
```

## Exit codes

| Exit code | Meaning |
|-----------|---------|
| `0` | All checks passed |
| `1` | One or more checks failed (ERROR severity) |

WARNING-severity checks never cause a non-zero exit code.

---

## Check Reference

### VC1xx — Configuration

Validates config files (`docker-compose.yml`, `.env.sample`, `config.yml.sample`).

| Code | Severity | Name | Description |
|------|----------|------|-------------|
| VC101 | ERROR | `config-token-default` | `OPENCTI_TOKEN` must default to `ChangeMe` (exact case) |
| VC102 | ERROR | `config-url-default` | `OPENCTI_URL` must default to `http://localhost` (no port) |
| VC103 | ERROR | `config-variable-prefix` | Env vars must use `OPENCTI_`, `CONNECTOR_`, or `<CONNECTOR_NAME>_` prefix |
| VC104 | ERROR | `config-file-samples` | Must have `config.yml.sample` + `docker-compose.yml` or `.env.sample`; `ChangeMe` for values without defaults; defaults must be commented |
| VC105 | ERROR | `no-absolute-import-date` | Import start dates must use ISO 8601 duration (`P30D`), not absolute dates (`2020-01-01`) |

### VC2xx — Metadata

Validates connector metadata (manifest, identity).

| Code | Severity | Name | Description |
|------|----------|------|-------------|
| VC202 | ERROR | `manifest-container-image` | `container_version` must be `"rolling"`, `container_image` must match `opencti/connector-<dirname>` |

### VC3xx — Code

Validates Python source code patterns. Uses AST analysis for structural checks.

| Code | Severity | Scope | Name | Description |
|------|----------|-------|------|-------------|
| VC301 | ERROR | Common | `author-defined` | Connector must define an author Identity (Organization) |
| VC302 | ERROR | Common | `author-referenced-on-entities` | Author must be referenced on STIX entities via `created_by_ref` |
| VC303 | ERROR | Common | `connector-type-hardcoded` | `CONNECTOR_TYPE` must be hardcoded in code, not read from env |
| VC304 | ERROR | Enrichment | `markings-checked` | TLP markings must be checked via `check_max_tlp` before processing |
| VC305 | ERROR | Common | `sdk-base-settings` | Connector must use `BaseConnectorSettings` from connectors-sdk |
| VC306 | WARNING | Common | `log-level-default-error` | Log level should default to `error` |
| VC307 | WARNING | Common | `except-logging-level` | Except blocks should use `error`/`warning` logging, not `debug`/`info` |
| VC308 | ERROR | Common | `main-traceback` | `main.py` must use `traceback` for error handling |
| VC309 | ERROR | Common | `absolute-imports-only` | No relative imports — use absolute imports only |
| VC310 | ERROR | Common | `external-references-not-default` | External references must not be added by default to all entities; only on Identity |
| VC311 | WARNING | Common | `tlp-markings-on-entities` | STIX entities should include TLP markings |
| VC312 | ERROR | Common | `cleanup-inconsistent-bundle` | `send_stix2_bundle()` must use `cleanup_inconsistent_bundle=True` |
| VC313 | ERROR | Common | `pycti-generate-id` | STIX SDO/SRO objects must use `pycti.XXX.generate_id()` for deterministic IDs |
| VC314 | ERROR | External Import | `auto-backpressure` | Must use `schedule_process()` or `schedule_iso()` for scheduling |
| VC315 | ERROR | External Import | `work-initiated` | Must call `initiate_work()` before processing |
| VC316 | ERROR | External Import | `work-closed` | Must close work with `to_processed()` after processing |
| VC317 | WARNING | External Import | `initiate-work-conditional` | `initiate_work` should only be called when data is available |
| VC318 | ERROR | Enrichment | `helper-listen` | Must use `self.helper.listen()` for message callback |
| VC319 | WARNING | Enrichment | `scope-fallback-bundle` | Must return original bundle when entity is not in scope |
| VC320 | ERROR | Enrichment | `tlp-access-control` | Must enforce TLP access control (extract → check → reject) |
| VC321 | ERROR | Enrichment | `playbook-compatible` | Must set `playbook_compatible=True` in helper constructor |
| VC322 | ERROR | Enrichment | `former-bundle-read` | Must read `data['stix_objects']` for playbook compatibility |
| VC323 | ERROR | Stream | `helper-listen-stream` | Must use `self.helper.listen_stream()` |
| VC324 | WARNING | Common | `relationship-start-stop-time` | Relationship should not set both `start_time` and `stop_time` (overloads Redis with time-bucketed duplicates) |

### VC4xx — Docker

Validates Dockerfile and docker-compose configuration.

| Code | Severity | Name | Description |
|------|----------|------|-------------|
| VC401 | ERROR | `docker-compose-image` | Image must use `:latest` tag and name must match directory (`opencti/connector-<dirname>:latest`) |
| VC402 | ERROR | `no-entrypoint-sh` | Dockerfile must not use `entrypoint.sh` — use direct `ENTRYPOINT ["python", ...]` |

### VC5xx — Deprecation

Detects deprecated patterns that must be removed for Verified status.

| Code | Severity | Name | Description |
|------|----------|------|-------------|
| VC501 | ERROR | `no-legacy-interval` | Must use `CONNECTOR_DURATION_PERIOD` (ISO 8601), not `*_INTERVAL` variables or `schedule_unit()` |
| VC502 | ERROR | `no-deprecated-report-status` | Must not use `x_opencti_report_status` (deprecated, non-functional). `x_opencti_workflow_id` emits a WARNING |
| VC503 | ERROR | `no-deprecated-helper-logger` | Must use `helper.connector_logger.{level}()` instead of `helper.log_{level}()` |
| VC504 | ERROR | `no-deprecated-confidence` | Must not use `confidence` level (deprecated since OpenCTI 6.0 — managed by platform policies) |
| VC505 | WARNING | `no-direct-api-calls` | Should not use `helper.api.*` for direct GraphQL calls (except `api.work`, `api.vocabulary`, `api.label`, etc.) |
| VC506 | ERROR | `no-update-existing-data` | Must not use `UPDATE_EXISTING_DATA` (no longer in helper). Exception: `opencti` datasets connector |

---

## Architecture

```
connector_linter/
├── __init__.py          # Version
├── __main__.py          # Click CLI (check, list commands)
├── models.py            # ConnectorContext, CheckFinding, CheckResult, Severity
├── registry.py          # CheckRegistry — decorator-based registration
├── runner.py            # Auto-discovers and executes checks
├── formatters.py        # Output: text (ANSI), JSON, GitHub Actions
└── checks/              # All check modules, auto-discovered
    ├── vc1xx_config/     # Configuration checks
    │   ├── _helpers.py   # Env var parsing, config file utilities
    │   ├── vc101_*.py
    │   └── ...
    ├── vc2xx_metadata/   # Metadata checks
    ├── vc3xx_code/       # Code structure checks
    │   ├── _helpers.py   # AST + regex helpers
    │   ├── vc301_*.py
    │   └── ...
    ├── vc4xx_docker/     # Docker checks
    └── vc5xx_deprecation/ # Deprecation checks
```

### Key concepts

- **`ConnectorContext`** — Loaded once per connector. Contains the path, connector type (auto-detected from parent dir), manifest, file lists, and structural flags.
- **`CheckRegistry`** — Singleton registry. Checks register themselves via the `@CheckRegistry.register()` decorator.
- **`CheckFinding`** — Lightweight dataclass returned by check functions. Contains only check-specific data: `message`, `passed`, `file_path`, `line`, `suggestion`, and an optional `severity` override.
- **`CheckResult`** — Full result produced by the runner. The runner hydrates each `CheckFinding` with `code`, `name`, and `severity` from the `CheckDescriptor`, so checks never repeat those fields.
- **Auto-discovery** — `runner.py` uses `pkgutil.walk_packages()` to find all modules under `checks/`. Modules prefixed with `_` (like `_helpers.py`) are skipped.

### Severity semantics

| Severity | `passed=True` | `passed=False` |
|----------|--------------|----------------|
| ERROR | Check passes ✓ | Blocking failure ✗ (causes exit code 1) |
| WARNING | Non-blocking info | Non-blocking warning (never causes exit code 1) |

---

## Adding a new check

### 1. Choose the right category and code

| Category | Prefix | For |
|----------|--------|-----|
| Configuration | `VC1xx` | Config files (env vars, YAML, settings) |
| Metadata | `VC2xx` | Manifest, connector identity |
| Code | `VC3xx` | Python source patterns (AST/regex) |
| Docker | `VC4xx` | Dockerfile, docker-compose |
| Deprecation | `VC5xx` | Deprecated patterns to remove |

Pick the next number in the category (e.g., if the last is `VC324`, use `VC325`).

### 2. Create the check file

Create a new file in the appropriate package:

```bash
# Example: new deprecation check
touch connector_linter/checks/vc5xx_deprecation/vc507_my_new_check.py
```

### 3. Write the check

```python
"""VC507 — Short description of what this check validates.

Longer explanation of why this matters, what the correct pattern is,
and any references to PRs/issues.

Scope: Common | EXTERNAL_IMPORT | INTERNAL_ENRICHMENT | STREAM
"""

from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry


@CheckRegistry.register(
    code="VC507",
    name="my-check-name",                # kebab-case short name
    description="One-line description",  # shown in `list` output
    severity=Severity.ERROR,             # ERROR or WARNING
)
def check_my_new_check(ctx: ConnectorContext) -> list[CheckFinding]:
    """Implement the check logic here."""
    
    # Use ctx.path, ctx.connector_type, ctx.manifest, ctx.src_files, etc.
    
    # Scope to specific connector types if needed:
    if ctx.connector_type and ctx.connector_type != "EXTERNAL_IMPORT":
        return []  # skip — not applicable
    
    # Return PASS result
    return [
        CheckFinding(
            message="Everything looks good ✓",
            passed=True,
        )
    ]
    
    # Or return FAIL with suggestion
    return [
        CheckFinding(
            message="Problem description",
            passed=False,
            file_path=ctx.path / "src/connector.py",  # Path object (relative joined with ctx.path)
            line=42,
            suggestion="How to fix this issue.",
        )
    ]
```

### 4. Update the package `__init__.py`

Add the new check to the docstring in the category's `__init__.py`:

```python
"""VC5xx — Deprecation checks.
...
VC506  no-update-existing-data    Must not use deprecated UPDATE_EXISTING_DATA
VC507  my-check-name              One-line description
"""
```

### 5. Available helpers

#### Configuration helpers (`vc1xx_config/_helpers.py`)

```python
from connector_linter.checks.vc1xx_config._helpers import (
    extract_all_env_vars,        # Returns list[EnvVar] from docker-compose + .env.sample
    extract_env_vars_from_docker_compose,
    extract_env_vars_from_env_sample,
    derive_connector_prefixes,   # dirname → ["ABUSE_SSL", "ABUSESSL"]
    find_bad_changeme_values,    # Finds wrong-case ChangeMe
)
```

#### Code helpers (`vc3xx_code/_helpers.py`)

```python
from connector_linter.checks.vc3xx_code._helpers import (
    read_all_python_sources,     # Returns dict[Path, source_code]
    parse_sources,               # Returns dict[Path, ast.Module]
    find_pattern_locations,      # Regex search across all sources → list[tuple[Path, int, str]]
    find_imports,                # Find import statements by module/name pattern → list[ImportInfo]
    find_classes,                # Find class definitions by base class → list[ClassInfo]
    find_calls_in_stmts,         # Find function/method calls (with receiver) → list[CallInfo]
    find_field_defaults,         # Find default values in class fields → list[FieldDefaultInfo]
    find_except_blocks,          # Find except blocks with their logging → list[ExceptBlockInfo]
)
```

### 6. Test your check

```bash
# Run against a known connector
uv run connector-linter check ../../external-import/mandiant --select VC507

# Run against a connector that should fail
uv run connector-linter check ../../external-import/alienvault --select VC507

# Verify it shows up in the list
uv run connector-linter list | grep VC507
```

### Tips

- **Use AST over regex** when checking Python code structure (function calls, keyword arguments, class definitions). It's more reliable and won't match inside strings or comments.
- **Use regex** for simple text patterns in non-Python files (config, Dockerfile, YAML).
- **Scope checks** to specific connector types by checking `ctx.connector_type` early and returning `[]` if not applicable.
- **Multiple results** — a check can return multiple `CheckFinding` items (e.g., one per file where a violation was found). The runner enriches each with `code`/`name`/`severity` from the descriptor.
- **Cross-package imports** are fine — deprecation checks commonly use helpers from `vc1xx_config/_helpers.py` and `vc3xx_code/_helpers.py`.
- **`_`-prefixed modules** are ignored by auto-discovery — use this for helper modules.

---

## Running the linter in CI

### GitHub Actions

```yaml
- name: Lint connector
  run: |
    cd shared/connector_linter
    uv run connector-linter check ../../external-import/${{ matrix.connector }} --format github
```

The `--format github` output produces `::error` / `::warning` annotations that appear inline in PR diffs.

### JSON output for scripting

```bash
connector-linter check ./connector --format json | jq '.score_pct'
```

The JSON output includes:
- `results`: array of check results with `code`, `passed`, `message`, `severity`, `suggestion`
- `summary`: `total`, `passed`, `failed`, `errors`, `warnings`
- `score_pct`: percentage score (0–100)
