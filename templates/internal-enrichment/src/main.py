"""Connector entry point.

This script creates the parts of the connector and starts it. Read this
file first: it shows, in order, everything an `INTERNAL_ENRICHMENT`
connector needs to run.

Steps:
    1. Load and validate the configuration (`ConnectorSettings`). The values
       come from environment variables or `config.yml` -- see
       `connector/settings.py`.
    2. Create the enrichment processors. Each processor enriches one or more
       entity types: it fetches data about the entity from the external
       source, then converts this data to STIX -- see
       `connector/enrichment_processors/`.
    3. Create the connector and start it. `InternalEnrichmentConnector`
       (from `connectors-sdk`) listens to the enrichment messages. For each
       message, it checks the connector scope and the entity TLP, calls the
       processor that handles the entity, then sends the bundle to OpenCTI.
       It also handles playbooks, errors and the work status, so you only
       write the processors' `collect()` and `transform()` methods.

If the connector fails to start, the full traceback is printed and the
process exits with a non-zero code, so that Docker (or any tool that runs
the connector) sees the failure.

TODO:
    - [ ] Add one processor per group of entity types your connector enriches.
"""

import traceback

from connector import ConnectorSettings
from connector.enrichment_processors import IPv4Processor
from connectors_sdk import BaseEnrichmentProcessor
from connectors_sdk import InternalEnrichmentConnector as TemplateConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()

        enrichment_processors: list[BaseEnrichmentProcessor[ConnectorSettings]] = [
            IPv4Processor(),
        ]

        connector = TemplateConnector(
            settings=settings,
            enrichment_processors=enrichment_processors,
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
