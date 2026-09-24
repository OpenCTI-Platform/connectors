"""Persisted checkpoints: the newest `date_added` seen per collection, so a
run asks the TAXII server only for objects added since the previous run."""

from datetime import datetime

from connectors_sdk import ExternalImportConnectorState


class ConnectorState(ExternalImportConnectorState):
    attackers_added_after: datetime | None = None
    exploiters_added_after: datetime | None = None
    cve_probers_added_after: datetime | None = None
    malware_infrastructure_added_after: datetime | None = None
