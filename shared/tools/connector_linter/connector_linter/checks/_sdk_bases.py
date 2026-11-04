"""Names of the connectors-sdk base classes recognised by several checks.

Kept in one place so VC104, VC303 and VC305 stay in sync when the SDK adds a
connector type.
"""

# ---------------------------------------------------------------------------
# Per-type config classes: each one hardcodes the connector ``type``, so
# inheriting from one is the preferred way to set it.
# ---------------------------------------------------------------------------
SDK_CONNECTOR_CONFIG_BASE_NAMES = (
    "BaseExternalImportConnectorConfig",
    "BaseInternalEnrichmentConnectorConfig",
    "BaseStreamConnectorConfig",
    "BaseInternalExportFileConnectorConfig",
    "BaseInternalImportFileConnectorConfig",
)

# ---------------------------------------------------------------------------
# Per-type settings classes (subclasses of BaseConnectorSettings): each one
# narrows its ``connector`` field to the matching per-type config class.
# ---------------------------------------------------------------------------
SDK_CONNECTOR_SETTINGS_BASE_NAMES = (
    "BaseExternalImportConnectorSettings",
    "BaseInternalEnrichmentConnectorSettings",
    "BaseStreamConnectorSettings",
    "BaseInternalExportFileConnectorSettings",
    "BaseInternalImportFileConnectorSettings",
)

# ---------------------------------------------------------------------------
# Accepted settings bases: the generic class plus the per-type ones.
# ---------------------------------------------------------------------------
SDK_SETTINGS_BASE_NAMES = ("BaseConnectorSettings", *SDK_CONNECTOR_SETTINGS_BASE_NAMES)
