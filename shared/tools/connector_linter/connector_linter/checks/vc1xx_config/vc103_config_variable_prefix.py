"""VC103 — Configuration variables must use proper prefixes.

Every environment variable in ``docker-compose.yml`` and ``.env.sample``
must be prefixed with one of:

- ``OPENCTI_`` — platform connection variables
- ``CONNECTOR_`` — pycti connector variables
- ``<CONNECTOR_NAME>_`` — connector-specific variables

The connector name prefix is derived from the directory name
(uppercased, hyphens converted to underscores or removed).

Scope: Common (all connector types).
"""

from pathlib import Path

from connector_linter.checks.vc1xx_config._helpers import (
    derive_connector_prefixes,
    extract_all_env_vars,
)
from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Standard env-var prefixes used by all connectors:
#   OPENCTI_   — platform connection settings (URL, token)
#   CONNECTOR_ — pycti framework settings (id, name, scope, log_level)
#
# Connector-specific variables use a prefix derived from the directory name
# (e.g. MANDIANT_, ABUSE_SSL_).  See derive_connector_prefixes().
# ---------------------------------------------------------------------------
_STANDARD_PREFIXES = ("OPENCTI_", "CONNECTOR_")


@CheckRegistry.register(
    code="VC103",
    name="config-variable-prefix",
    description="Env vars must use OPENCTI_, CONNECTOR_, or <CONNECTOR_NAME>_ prefix",
    severity=Severity.WARNING,  # this is a warning because it's a style issue, not a correctness issue
)
def check_config_variable_prefix(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that all env vars use valid prefixes."""
    all_vars = extract_all_env_vars(ctx)

    if not all_vars:
        return [
            CheckFinding(
                message="No configuration file found (docker-compose.yml or .env.sample)",
                severity=Severity.WARNING,
                suggestion="Add a docker-compose.yml with environment variables.",
            ),
        ]

    # Build the full list of valid prefixes:
    #   ["OPENCTI_", "CONNECTOR_"] + ["MANDIANT_"] (or ["ABUSE_SSL_", "ABUSESSL_"])
    # An underscore is appended to each connector prefix so the match is
    # strict — "MANDIANT" alone should not pass, only "MANDIANT_<setting>".
    connector_prefixes = derive_connector_prefixes(ctx)
    valid_prefixes = list(_STANDARD_PREFIXES) + [f"{connector_prefixes}_"]

    bad_vars: list[tuple[str, Path, int]] = []  # (name, path, line)

    # Check every env var against ALL valid prefixes.
    # A var is valid if it starts with at least one of them.
    for var in all_vars:
        if any(var.name.startswith(prefix) for prefix in valid_prefixes):
            continue
        bad_vars.append((var.name, var.file_path, var.line))

    if not bad_vars:
        prefix_display = f"{connector_prefixes}_"
        return [
            CheckFinding(
                message=f"All env vars use valid prefixes (OPENCTI_, CONNECTOR_, {prefix_display})",
                severity=Severity.INFO,
            ),
        ]

    results: list[CheckFinding] = []
    # Prefer the underscore form (e.g. ABUSE_SSL over ABUSESSL) as the
    # canonical prefix for suggestions.  The underscore variant is always
    # the dirname with hyphens replaced by underscores.
    canonical = ctx.path.name.upper().replace("-", "_")
    for var_name, file_path, line in bad_vars:
        results.append(
            CheckFinding(
                message=f"{var_name} has no valid connector prefix",
                severity=Severity.WARNING,  # this is technically a pass since the var is valid, just not styled correctly
                file_path=file_path,
                line=line,
                suggestion=(
                    f"Prefix with {canonical}_ "
                    f"(e.g. {canonical}_{var_name}). "
                    f"Accepted prefixes: OPENCTI_, CONNECTOR_, {canonical}_."
                ),
            ),
        )

    return results
