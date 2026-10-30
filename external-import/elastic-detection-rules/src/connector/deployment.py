"""Deployment of rule Indicators on the Security Platform.

The deployment is a ``deployed-on`` relationship (Indicator -> Security
Platform) carrying ``deployment_status``, ``external_id``, ``deployed_at``
and ``last_sync_at``. Platforms that do not define this relationship get a
``related-to`` relationship describing the deployment instead.
"""

from pycti import OpenCTIConnectorHelper

DEPLOYED_ON = "deployed-on"
RELATED_TO = "related-to"

# Values of ``deployment_status`` written by this connector.
STATUS_ACTIVE = "active"  # present and enabled
STATUS_DEPLOYED = "deployed"  # present but disabled
STATUS_REMOVED = "removed"  # seen in the previous run, gone now

_SCHEMA_QUERY = """
    query SchemaRelationsTypesMapping {
        schemaRelationsTypesMapping {
            key
            values
        }
    }
"""
_INDICATOR_TO_PLATFORM = "Indicator_SecurityPlatform"


def is_deployed_on_supported(helper: OpenCTIConnectorHelper) -> bool:
    """Tell whether the platform defines ``deployed-on`` for Indicators.

    Never raises: a platform that cannot answer is treated as one without
    the relationship, so the run degrades to ``related-to``.
    """
    try:
        result = helper.api.query(_SCHEMA_QUERY)
    except Exception as err:  # noqa: BLE001 - feature detection never fails a run
        helper.connector_logger.warning(
            "Could not read the relationship schema of the platform",
            {"error": str(err)},
        )
        return False
    data = result.get("data") if isinstance(result, dict) else None
    mapping = (
        data.get("schemaRelationsTypesMapping") if isinstance(data, dict) else None
    )
    if not isinstance(mapping, list):
        return False
    return any(
        entry.get("key") == _INDICATOR_TO_PLATFORM
        and DEPLOYED_ON in (entry.get("values") or [])
        for entry in mapping
        if isinstance(entry, dict)
    )
