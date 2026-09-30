"""VC104 — Configuration file samples must exist and follow conventions.

A verified connector **must** provide:

1. ``config.yml.sample`` (at root or under ``src/``).
2. **Either** ``.env.sample`` **or** ``docker-compose.yml`` with an
   ``environment:`` section.
3. All placeholder values use exact ``ChangeMe`` case (not ``CHANGEME``).
4. Configuration is **not** hardcoded in a Python file.
5. Settings **with** defaults must be **commented** out.
6. Settings **without** defaults must use ``ChangeMe`` (uncommented).

Scope: Common (all connector types).
"""

import ast
import re
from pathlib import Path

from connector_linter.checks.vc1xx_config._helpers import (
    extract_env_vars_from_docker_compose,
    find_bad_changeme_values,
    has_docker_compose_env,
    has_env_sample,
)
from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Regex: config-like variable names that should NOT be hardcoded in Python.
#
# Matches uppercase identifiers ending with common config suffixes:
#   URL, TOKEN, KEY, SECRET, PASSWORD, HOST, PORT, API, ENDPOINT, BASE_URL
# The optional trailing "s" handles plurals (e.g. ENDPOINTS).
# Case-insensitive so it also catches mixed-case Python names.
#
# Examples that match: API_KEY, BASE_URL, OPENCTI_TOKEN, MY_SECRETS
# ---------------------------------------------------------------------------
_CONFIG_NAME_RE = re.compile(
    r"^[A-Z_]*(?:URL|TOKEN|KEY|SECRET|PASSWORD|HOST|PORT|API|ENDPOINT|BASE_URL)s?$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Variables that must ALWAYS remain uncommented in docker-compose.yml.
#
# OPENCTI_URL and OPENCTI_TOKEN are required for every connector to connect
# to the platform.  Unlike optional settings (which should be commented out
# when they have sane defaults), these two must always be visible and active
# so the user immediately knows they need to set them.
# ---------------------------------------------------------------------------
_ALWAYS_UNCOMMENTED = {"OPENCTI_URL", "OPENCTI_TOKEN"}


def _find_hardcoded_python_config(ctx: ConnectorContext) -> list[tuple[Path, int, str]]:
    """Detect module-level hardcoded config assignments in Python files.

    Returns (file_path, line, variable_name) for each suspicious assignment.
    Excludes settings.py and files that import pydantic / os.environ.
    """
    src_dir = ctx.path / "src"
    if not src_dir.is_dir():
        return []

    hits: list[tuple[Path, int, str]] = []

    for py_file in src_dir.rglob("*.py"):
        fname = py_file.name
        # settings.py is the *expected* place for config-variable declarations
        # (Pydantic settings classes).  Skip it — it's not "hardcoded".
        if fname == "settings.py":
            continue
        try:
            source = py_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        # ---------------------------------------------------------------------------
        # Skip files that already use a proper config-loading mechanism.
        #
        # If the file references BaseSettings, get_config_variable, os.environ,
        # etc., the developer is loading config at runtime — not hardcoding it.
        # Flagging these would produce false positives.
        # ---------------------------------------------------------------------------
        if any(
            kw in source
            for kw in (
                "BaseSettings",
                "BaseConnectorSettings",
                "get_config_variable",
                "os.environ",
                "os.getenv",
                "pydantic_settings",
            )
        ):
            continue

        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue

        # Walk only top-level assignments (module scope) — nested assignments
        # inside functions are less suspicious (they may be local defaults).
        for node in ast.iter_child_nodes(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                name = target.id
                if not _CONFIG_NAME_RE.match(name):
                    continue
                # Only flag hardcoded string/number values (not function
                # calls, attribute lookups, or other dynamic expressions).
                if isinstance(node.value, ast.Constant) and isinstance(
                    node.value.value,
                    (str, int, float),
                ):
                    rel = py_file.relative_to(ctx.path)
                    hits.append((rel, node.lineno, name))

    return hits


def _check_config_yml_sample_exists(ctx: ConnectorContext) -> CheckFinding:
    """Check that config.yml.sample exists at root"""
    config_yml = ctx.path / "config.yml.sample"
    if config_yml.is_file():
        rel = config_yml.relative_to(ctx.path)
        return CheckFinding(
            message=f"config.yml.sample found at {rel} (root)",
            severity=Severity.INFO,
            file_path=config_yml,
            line=1,
        )
    elif (ctx.path / "src/config.yml.sample").is_file():
        rel = Path("src/config.yml.sample")
        return CheckFinding(
            message=f"config.yml.sample found at {rel} (src/)",
            severity=Severity.WARNING,
            file_path=ctx.path / rel,
            line=1,
            suggestion="Move config.yml.sample to root directory for better "
            "visibility and convention.",
        )
    else:
        return CheckFinding(
            message="config.yml.sample not found",
            severity=Severity.ERROR,
            suggestion="Add a config.yml.sample at root.",
        )


def check_docker_compose_or_env_sample_exists(ctx: ConnectorContext) -> CheckFinding:
    """Check that either docker-compose.yml (with env) or .env.sample exists."""
    has_compose = has_docker_compose_env(ctx)
    has_env = has_env_sample(ctx)

    if has_compose or has_env:
        source = "docker-compose.yml" if has_compose else ".env.sample"
        return CheckFinding(
            message=f"Environment config available via {source}",
            severity=Severity.INFO,
        )
    else:
        return CheckFinding(
            message="No docker-compose.yml (with env vars) or .env.sample found",
            severity=Severity.ERROR,
            suggestion=(
                "Add a docker-compose.yml with an environment section "
                "or an .env.sample file."
            ),
        )


def check_change_me_consistency(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that all placeholder values use exact ChangeMe case."""
    config_yml = ctx.path / "config.yml.sample"
    files_to_check: list[Path] = []
    compose_path = ctx.path / "docker-compose.yml"
    if compose_path.is_file():
        files_to_check.append(compose_path)
    env_path = ctx.path / ".env.sample"
    if env_path.is_file():
        files_to_check.append(env_path)
    if config_yml.is_file():
        files_to_check.append(config_yml)

    bad_hits: list[tuple[Path, int, str]] = []
    for fpath in files_to_check:
        bad_hits.extend(
            (hit.file_path, hit.line, hit.raw_value)
            for hit in find_bad_changeme_values(fpath)
        )

    if bad_hits:
        results: list[CheckFinding] = []
        for fpath, line_no, raw_val in bad_hits:
            results.append(
                CheckFinding(
                    message=f"'{raw_val}' should be 'ChangeMe'",
                    severity=Severity.ERROR,
                    file_path=fpath,
                    line=line_no,
                    suggestion="Use exact 'ChangeMe' (not CHANGEME or changeme).",
                ),
            )
        return results
    else:
        return [
            CheckFinding(
                message="All placeholder values use correct ChangeMe case",
                severity=Severity.INFO,
            ),
        ]


def check_commented_convention(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that settings with defaults are commented out, and without defaults use ChangeMe.

    Convention for docker-compose.yml environment sections:
      - Variables WITH a default value (e.g. ``LOG_LEVEL=info``) should be
        commented out.  The user uncomments them only when they want to
        override the built-in default.
      - Variables WITHOUT a default (e.g. ``API_KEY=ChangeMe``) must be
        uncommented so the user immediately sees they need to fill them in.

    OPENCTI_URL and OPENCTI_TOKEN are exempt — they are always uncommented
    because every connector needs them regardless of defaults.
    """
    compose_vars = extract_env_vars_from_docker_compose(ctx)
    if not compose_vars:
        return []

    results: list[CheckFinding] = []
    for var in compose_vars:
        is_changeme = var.value.lower() == "changeme"
        is_env_ref = var.value.startswith("${") and var.value.endswith("}")

        if var.name in _ALWAYS_UNCOMMENTED:
            continue

        # Setting is neither:
        #  - 'ChangeMe'
        #  - an environment reference
        #  - not commented out
        # → it has a default value but is not following the convention of being commented out.
        if not is_changeme and not is_env_ref and not var.is_commented:
            rel = var.file_path.relative_to(ctx.path)
            results.append(
                CheckFinding(
                    message=(
                        f"{rel}:{var.line}: {var.name}={var.value} has a "
                        f"default — should be commented out"
                    ),
                    severity=Severity.WARNING,
                    file_path=var.file_path,
                    line=var.line,
                    suggestion=(
                        f"Comment out {var.name} since it has a default "
                        f"value. Users can uncomment to override."
                    ),
                ),
            )

    return results


@CheckRegistry.register(
    code="VC104",
    name="config-file-samples",
    description="Config samples (config.yml.sample + docker-compose/env) must exist",
    severity=Severity.ERROR,
)
def check_config_file_samples(ctx: ConnectorContext) -> list[CheckFinding]:
    """Validate configuration file samples exist and follow conventions."""
    results: list[CheckFinding] = []

    # --- Sub-check A: config.yml.sample exists ---
    # Every connector must ship a YAML config sample so users can run
    # the connector outside Docker (e.g. direct Python invocation).
    results.append(_check_config_yml_sample_exists(ctx))

    # --- Sub-check B: docker-compose.yml or .env.sample exists ---
    # At least one Docker-friendly config file must be present so
    # users can deploy via docker-compose without extra steps.
    results.append(check_docker_compose_or_env_sample_exists(ctx))

    # --- Sub-check C: ChangeMe case consistency ---
    # All placeholder values must use exact "ChangeMe" casing per the
    # January 2026 alignment (not CHANGEME, changeme, etc.).
    results.extend(check_change_me_consistency(ctx))

    # --- Sub-check D: commented/uncommented convention (docker-compose.yml) ---
    # Settings WITH defaults → must be commented out (user uncomments to override)
    # Settings WITHOUT defaults → must use ChangeMe (uncommented, user fills in)
    # This makes docker-compose samples self-documenting.
    results.extend(check_commented_convention(ctx))

    # --- Sub-check E: No hardcoded Python configuration ---
    # Config values (URLs, tokens, keys) must come from env vars or settings
    # classes, never from hardcoded constants in Python source files.
    # Severity is WARNING because this is a best-practice
    # recommendation, not a hard blocker.
    hardcoded = _find_hardcoded_python_config(ctx)
    if hardcoded:
        for fpath, line_no, var_name in hardcoded:
            results.append(
                CheckFinding(
                    message=f"{var_name} appears hardcoded in Python",
                    severity=Severity.WARNING,
                    file_path=fpath,
                    line=line_no,
                    suggestion=(
                        "Move configuration to environment variables or "
                        "connectors-sdk settings, not hardcoded Python constants."
                    ),
                ),
            )

    return results
