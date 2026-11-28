"""Persisted checkpoint: the id of the last imported feed bundle."""

from connectors_sdk import ExternalImportConnectorState


class ConnectorState(ExternalImportConnectorState):
    last_bundle_id: str | None = None
