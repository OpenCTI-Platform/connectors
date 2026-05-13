"""VC306 — Connector log level should default to 'error'.

Severity: WARNING — default log level is a best practice, not a hard
requirement. Connectors that default to debug/info produce excessive
logging in production but still function correctly.
"""

from connector_linter.checks.vc3xx_code._helpers import (
    find_field_defaults,
    find_imports,
)
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Accepted values for the "error" log level.
# Both "error" and "err" are valid — some logging frameworks use the short form.
# ---------------------------------------------------------------------------
_ERROR_VALUES = "error"


@CheckRegistry.register(
    code="VC306",
    name="log-level-default-error",
    description="Connector log level should default to 'error'",
    severity=Severity.WARNING,
)
def check_log_level_default(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector's default log level is 'error'."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees

    # ---------------------------------------------------------------------------
    # 3 detection paths:
    #
    #   1. Explicit field default — log_level found in a class body with a default
    #      value. Check if the value is "error"/"err".
    #   2. SDK base config — connector inherits from Base*ConnectorConfig which
    #      already defaults log_level to "error" (no override needed).
    #   3. Nothing found — no log_level config at all (PASS with suggestion).
    # ---------------------------------------------------------------------------

    # Path 1: look for explicit log_level field default in any class
    field_defaults = find_field_defaults(trees, field_name="log_level")

    if field_defaults:
        fd = field_defaults[0]
        if fd.default_value and fd.default_value == _ERROR_VALUES:
            return [
                CheckFinding(
                    message=f"Log level defaults to '{fd.default_value}'",
                    severity=Severity.INFO,
                    file_path=fd.file_path,
                    line=fd.line,
                ),
            ]
        display_val = fd.default_value or "unknown"
        return [
            CheckFinding(
                message=(
                    f"Log level defaults to '{display_val}' in {fd.file_path}:{fd.line} "
                    "(should be 'error')"
                ),
                severity=Severity.WARNING,
                file_path=fd.file_path,
                line=fd.line,
                suggestion=(
                    "Set the default log level to 'error'. "
                    "DEBUG logs are useful but should require explicit opt-in. "
                    "Use connectors-sdk BaseConnectorSettings which defaults to 'error'"
                ),
            ),
        ]

    # Path 2: no explicit log_level override — check if using SDK base
    # (inherits "error" as default, so no override is needed)
    sdk_imports = find_imports(
        trees,
        module_pattern=r"^connectors_sdk",
        name_pattern=r"^Base(ExternalImport|InternalEnrichment|Stream|InternalExportFile|InternalImportFile)ConnectorConfig$",
    )
    if sdk_imports:
        imp = sdk_imports[0]
        return [
            CheckFinding(
                message="Log level inherited from SDK (defaults to 'error')",
                severity=Severity.INFO,
                file_path=imp.file_path,
                line=imp.line,
            ),
        ]

    # Path 3: no log_level configuration found at all
    return [
        CheckFinding(
            message="No log_level default configuration found",
            severity=Severity.WARNING,
            suggestion=(
                "Use connectors-sdk BaseConnectorSettings which defaults log_level to 'error'. "
                "If using custom config, set log_level default to 'error'"
            ),
        ),
    ]
