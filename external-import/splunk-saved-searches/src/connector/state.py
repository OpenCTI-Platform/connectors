"""Connector state persisted between runs."""

from connectors_sdk import ExternalImportConnectorState


class ConnectorState(ExternalImportConnectorState):
    """``last_run`` plus the rules seen during the previous run.

    ``deployed_rules`` maps the key of every rule imported by the previous
    run to its Indicator id, so a rule gone since then (or whose logic
    changed) gets the ``removed`` deployment status. ``pending_removals``
    keeps, as Indicator id -> rule id, the removals the platform could not
    be asked about, retried on the next run. ``platform_id`` is the Security
    Platform those deployments target: when the platform is renamed, they
    get the ``removed`` status on the former one.
    """

    deployed_rules: dict[str, str] | None = None
    pending_removals: dict[str, str] | None = None
    platform_id: str | None = None
