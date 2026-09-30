"""VC305 — Connector must implement Base Settings from connectors-sdk."""

import re

from connector_linter.checks.vc3xx_code._helpers import (
    find_classes,
    find_imports,
    find_pattern_locations,
)
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Legacy anti-pattern: get_config_variable() from pycti.
#
# This is the old-style configuration loading that manually reads each env
# variable via pycti's get_config_variable(). Should be replaced with
# connectors-sdk's typed Pydantic settings.
# ---------------------------------------------------------------------------
_LEGACY_CONFIG_PATTERNS = [
    re.compile(r"""get_config_variable\s*\(""", re.MULTILINE),
]


@CheckRegistry.register(
    code="VC305",
    name="sdk-base-settings",
    description="Connector must implement Base Settings from connectors-sdk",
    severity=Severity.ERROR,
)
def check_sdk_base_settings(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector uses BaseConnectorSettings from connectors-sdk."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees

    # ---------------------------------------------------------------------------
    # 4-tier detection (best → worst):
    #
    #   1. SDK import + class inheriting BaseConnectorSettings → PASS (best)
    #   2. Legacy get_config_variable() calls → FAIL (worst, must migrate)
    #   3. Custom pydantic_settings.BaseSettings → PASS with WARNING
    #   4. Nothing found → FAIL
    #
    # Note: SDK import AND class are both required — importing without
    # defining a subclass means the migration is incomplete.
    # ---------------------------------------------------------------------------

    # Tier 1: check for connectors-sdk BaseConnectorSettings (import + class)
    sdk_imports = find_imports(
        trees,
        module_pattern=r"^connectors_sdk",
        name_pattern=r"^BaseConnectorSettings$",
    )
    sdk_classes = find_classes(trees, base_name="BaseConnectorSettings")

    # Both import AND class must exist — import alone = incomplete migration
    if sdk_imports and sdk_classes:
        cls = sdk_classes[0]
        return [
            CheckFinding(
                message="BaseConnectorSettings implemented",
                severity=Severity.INFO,
                file_path=cls.file_path,
                line=cls.line,
            ),
        ]

    # Tier 2: check for legacy get_config_variable (regex — AST not needed here)
    legacy_hits = find_pattern_locations(sources, _LEGACY_CONFIG_PATTERNS)
    if legacy_hits:
        file_path, line, _ = legacy_hits[0]
        return [
            CheckFinding(
                message=(
                    f"Legacy get_config_variable() found in {file_path}:{line} "
                    f"({len(legacy_hits)} call(s) total)"
                ),
                severity=Severity.ERROR,
                file_path=file_path,
                line=line,
                suggestion=(
                    "Replace get_config_variable() calls with connectors-sdk "
                    "BaseConnectorSettings. Create a settings.py with a class "
                    "inheriting BaseConnectorSettings and use typed Pydantic fields "
                    "for configuration (see connectors-sdk documentation)"
                ),
            ),
        ]

    # Tier 3: check for custom pydantic_settings.BaseSettings (intermediate)
    # This is acceptable but not ideal — connectors-sdk provides more features
    pydantic_imports = find_imports(
        trees,
        module_pattern=r"^pydantic_settings$",
        name_pattern=r"^BaseSettings$",
    )
    if pydantic_imports:
        pydantic_classes = find_classes(trees, base_name="BaseSettings")
        if pydantic_classes:
            cls = pydantic_classes[0]
            return [
                CheckFinding(
                    message=(
                        f"Custom pydantic BaseSettings found in {cls.file_path}:{cls.line} "
                        "instead of connectors-sdk BaseConnectorSettings"
                    ),
                    severity=Severity.WARNING,
                    file_path=cls.file_path,
                    line=cls.line,
                    suggestion=(
                        "Consider migrating to connectors-sdk BaseConnectorSettings "
                        "which provides built-in config loading (env, YAML, .env), "
                        "deprecation management, and JSON schema generation"
                    ),
                ),
            ]
        imp = pydantic_imports[0]
        return [
            CheckFinding(
                message=(
                    f"Custom pydantic BaseSettings imported in {imp.file_path}:{imp.line} "
                    "instead of connectors-sdk BaseConnectorSettings"
                ),
                severity=Severity.WARNING,
                file_path=imp.file_path,
                line=imp.line,
                suggestion=(
                    "Consider migrating to connectors-sdk BaseConnectorSettings "
                    "which provides built-in config loading (env, YAML, .env), "
                    "deprecation management, and JSON schema generation"
                ),
            ),
        ]

    # No settings pattern found at all
    return [
        CheckFinding(
            message="No settings implementation found in connector source",
            severity=Severity.ERROR,
            suggestion=(
                "Create a settings.py file with a class inheriting from "
                "connectors_sdk.BaseConnectorSettings. Use the appropriate "
                "typed connector config (e.g. BaseExternalImportConnectorConfig) "
                "and define connector-specific settings with BaseConfigModel"
            ),
        ),
    ]
