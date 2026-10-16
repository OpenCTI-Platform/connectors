"""Connector state persisted between runs."""

from connectors_sdk import ExternalImportConnectorState


class ConnectorState(ExternalImportConnectorState):
    """``last_run`` plus the rules seen during the previous run.

    ``deployed_rules`` maps the external id of every rule imported by the
    previous run to its Indicator id, so a rule gone since then (or whose
    logic changed) gets the ``removed`` deployment status under the same
    external id. ``pending_removals`` keeps, as Indicator id -> external id,
    the removals the platform could not be asked about, retried on the next
    run. ``platform_id`` is the Security Platform those deployments target.
    When the targeted platform changes (renamed, or another configured
    platform), the deployments of the former one owe it a ``removed`` status:
    ``former_platform_removals`` keeps them per former platform until they
    are sent, while ``deployed_rules`` already follows the new platform.
    """

    deployed_rules: dict[str, str] | None = None
    pending_removals: dict[str, str] | None = None
    platform_id: str | None = None
    former_platform_removals: dict[str, dict[str, str]] | None = None
