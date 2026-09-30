"""VC102 — OPENCTI_URL must default to ``http://localhost``.

Following the January 2026 alignment commit, the default value for
``OPENCTI_URL`` must be ``http://localhost`` — no port, no path suffix,
and using ``localhost`` as the hostname (not ``opencti``).

Environment-variable references like ``${OPENCTI_URL}`` are acceptable.

Scope: Common (all connector types).
"""

from urllib.parse import urlparse

from connector_linter.checks.vc1xx_config._helpers import extract_all_env_vars
from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# The canonical default URL: http://localhost
#
# Why exactly this value?
# - No port: the platform port varies per deployment; including one (e.g.
#   :8080) couples the sample to a specific setup.
# - No path: trailing paths like /graphql are added by pycti internally.
# - "localhost": the sample is a local-dev starting point; Docker service
#   names like "opencti" belong in overrides, not defaults.
# ---------------------------------------------------------------------------
_VALID_URL = "http://localhost"


@CheckRegistry.register(
    code="VC102",
    name="config-url-default",
    description=f"OPENCTI_URL must default to {_VALID_URL}",
    severity=Severity.ERROR,
)
def check_config_url(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check OPENCTI_URL default value in configuration files."""
    all_vars = extract_all_env_vars(ctx)

    if not all_vars:
        return [
            CheckFinding(
                message="No configuration file found (docker-compose.yml or .env.sample)",
                severity=Severity.ERROR,
                suggestion="Add a docker-compose.yml with environment variables.",
            ),
        ]

    url_vars = [v for v in all_vars if v.name == "OPENCTI_URL" and not v.is_commented]

    if not url_vars:
        return [
            CheckFinding(
                message="OPENCTI_URL not found in configuration files",
                severity=Severity.ERROR,
                suggestion=f"Add OPENCTI_URL={_VALID_URL} to docker-compose.yml.",
            ),
        ]

    results: list[CheckFinding] = []
    for var in url_vars:
        value = var.value

        # Environment variable reference — acceptable
        if value.startswith("${") and value.endswith("}"):
            results.append(
                CheckFinding(
                    message=f"OPENCTI_URL uses env reference ({value})",
                    file_path=var.file_path,
                    line=var.line,
                    severity=Severity.INFO,
                ),
            )
            continue

        # ---------------------------------------------------------------------------
        # Validate the URL structure with urlparse.
        #
        # Each component is checked independently so we can give targeted
        # feedback (e.g. "remove the port" vs. "use http"):
        #   scheme   — must be "http" (not https, ftp, etc.)
        #   hostname — must be "localhost" (not "opencti" or an IP)
        #   port     — must be absent (None)
        #   path     — must be empty or "/" (no trailing path like /graphql)
        # ---------------------------------------------------------------------------
        parsed = urlparse(value)
        is_valid = (
            parsed.scheme == "http"
            and parsed.hostname == "localhost"
            and (parsed.port is None)
            and (parsed.path in ("", "/"))
        )

        if is_valid:
            results.append(
                CheckFinding(
                    message=f"OPENCTI_URL={_VALID_URL} ✓",
                    severity=Severity.INFO,
                    file_path=var.file_path,
                    line=var.line,
                ),
            )
        else:
            # Build a targeted suggestion listing only the specific issues,
            # so the developer knows exactly what to fix.
            suggestion_parts = []
            if parsed.port is not None:
                suggestion_parts.append("Remove the port number")
            if parsed.hostname and parsed.hostname != "localhost":
                suggestion_parts.append("Use 'localhost' as the hostname")
            if parsed.scheme != "http":
                suggestion_parts.append("Use 'http' as the scheme")
            if parsed.path not in ("", "/"):
                suggestion_parts.append("Remove the path suffix")
            suggestion_parts.append(f"Set to {_VALID_URL}")

            results.append(
                CheckFinding(
                    message=f"OPENCTI_URL={value} — expected {_VALID_URL}",
                    severity=Severity.ERROR,
                    file_path=var.file_path,
                    line=var.line,
                    suggestion=". ".join(suggestion_parts).capitalize() + ".",
                ),
            )

    return results
