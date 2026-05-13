"""VC101 — OPENCTI_TOKEN must default to ``ChangeMe``.

Following the January 2026 alignment commit, all configuration files
must use exactly ``ChangeMe`` as the placeholder value for
``OPENCTI_TOKEN`` (not ``CHANGEME``, ``changeme``, or a real token).

Environment-variable references like ``${OPENCTI_TOKEN}`` are acceptable.

Scope: Common (all connector types).
"""

from connector_linter.checks.vc1xx_config._helpers import extract_all_env_vars
from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry

_VALID_PLACEHOLDER = "ChangeMe"


@CheckRegistry.register(
    code="VC101",
    name="config-token-default",
    description="OPENCTI_TOKEN must default to ChangeMe",
    severity=Severity.ERROR,
)
def check_config_token(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check OPENCTI_TOKEN placeholder value in configuration files."""
    # Step 1: Gather all env vars from docker-compose.yml and .env.sample
    all_vars = extract_all_env_vars(ctx)

    if not all_vars:
        return [
            CheckFinding(
                message="No configuration file found (docker-compose.yml or .env.sample)",
                severity=Severity.ERROR,
                suggestion="Add a docker-compose.yml with environment variables.",
            ),
        ]

    # Step 2: Keep only uncommented OPENCTI_TOKEN entries.
    # Commented-out lines are informational — only active values matter.
    token_vars = [
        v for v in all_vars if v.name == "OPENCTI_TOKEN" and not v.is_commented
    ]

    if not token_vars:
        return [
            CheckFinding(
                message="OPENCTI_TOKEN not found in configuration files",
                severity=Severity.ERROR,
                suggestion="Uncomment or add OPENCTI_TOKEN=ChangeMe to docker-compose.yml.",
            ),
        ]

    # Step 3: Validate each OPENCTI_TOKEN occurrence.
    #
    # Decision tree for each value:
    #   ${...}      → PASS  (env reference — delegated to runtime)
    #   ChangeMe    → PASS  (canonical placeholder, exact case)
    #   changeme/*  → FAIL  (wrong case — must match Jan 2026 alignment)
    #   (empty)     → FAIL  (must have a placeholder)
    #   anything    → FAIL  (likely a real token committed by mistake)
    results: list[CheckFinding] = []
    for var in token_vars:
        value = var.value

        # ---------------------------------------------------------------------------
        # Environment variable reference — e.g. ${OPENCTI_TOKEN}
        #
        # docker-compose files often delegate to the host environment via
        # ${VAR} syntax.  This is perfectly fine — the actual secret is
        # never stored in the repo.
        # ---------------------------------------------------------------------------
        if value.startswith("${") and value.endswith("}"):
            results.append(
                CheckFinding(
                    message=f"OPENCTI_TOKEN uses env reference ({value})",
                    severity=Severity.INFO,
                    file_path=var.file_path,
                    line=var.line,
                ),
            )
            continue

        if value == _VALID_PLACEHOLDER:
            results.append(
                CheckFinding(
                    message="OPENCTI_TOKEN=ChangeMe ✓",
                    severity=Severity.INFO,
                    file_path=var.file_path,
                    line=var.line,
                ),
            )
        elif value.lower() == "changeme":
            # Case mismatch — the Jan 2026 alignment mandates exact "ChangeMe"
            results.append(
                CheckFinding(
                    message=f"OPENCTI_TOKEN={value} — wrong case",
                    severity=Severity.ERROR,
                    file_path=var.file_path,
                    line=var.line,
                    suggestion=f"Change from '{value}' to 'ChangeMe' (exact case).",
                ),
            )
        elif not value:
            results.append(
                CheckFinding(
                    message="OPENCTI_TOKEN has empty value",
                    severity=Severity.ERROR,
                    file_path=var.file_path,
                    line=var.line,
                    suggestion="Set OPENCTI_TOKEN=ChangeMe as the placeholder value.",
                ),
            )
        else:
            # Non-standard value — could be a real token accidentally committed.
            # Truncate to 20 chars to avoid leaking secrets in the output.
            results.append(
                CheckFinding(
                    message=f"OPENCTI_TOKEN has non-standard value: {value[:20]}{'...' if len(value) > 20 else ''}",
                    severity=Severity.ERROR,
                    file_path=var.file_path,
                    line=var.line,
                    suggestion=(
                        "Use 'ChangeMe' as the placeholder value. "
                        "Never commit real tokens."
                    ),
                ),
            )

    return results
