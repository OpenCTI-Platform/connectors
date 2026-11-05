"""Connector entry point.

This script wires together the objects defined elsewhere in this template
and starts the connector. Read this file first: it shows, in order, every
piece an `EXTERNAL_IMPORT` connector needs to run.

Steps performed below:
    1. Load and validate the connector's configuration (`ConnectorSettings`).
       Values come from environment variables or `config.yml`
       -- see `connector/settings.py` for the full list of available options.
    2. Load the connector's persisted state (`ConnectorState`), i.e. the
       checkpoints saved by the previous run (last processed date, page
       number, etc.) -- see `connector/state.py`.
    3. Build the list of data processors to run, one per data type/feature
       flag (e.g. reports, vulnerabilities). Each processor knows how to
       fetch its own data and convert it to STIX -- see `connector/data_processors/`.
    4. Instantiate the connector and start it. `connector.start()` is
       inherited from `ExternalImportConnector` (`connectors-sdk`) and
       runs the whole external-import loop for you: for each processor it
       calls `collect()` then `transform()`, sends the resulting STIX
       bundle to OpenCTI, persists the updated state, then waits
       `duration_period` before running again. You never write this loop
       yourself -- only the processors' `collect`/`transform`.

Notes:
    Any exception raised during startup or a run is caught here so it can
    be printed with a full traceback (useful when reading container logs),
    and the process exits with a non-zero status code so that Docker or any
    orchestration tool can detect the failure (and restart the container if
    configured to do so).

TODO:
    - [ ] Register one `if settings.template.import_x: data_processors.append(XProcessor())`
      line per data type/feature flag your connector supports.
"""

import traceback

from connector import ConnectorSettings, ConnectorState
from connector.data_processors import ReportsProcessor, VulnerabilitiesProcessor
from connectors_sdk import ExternalImportConnector as TemplateConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        state = ConnectorState()

        # TODO: add one entry per processor/feature flag you implement.
        data_processors = []
        if settings.template.import_vulnerabilities:
            data_processors.append(VulnerabilitiesProcessor())
        if settings.template.import_reports:
            data_processors.append(ReportsProcessor())

        connector = TemplateConnector(
            settings=settings,
            state=state,
            data_processors=data_processors,
        )
        connector.start()
    except Exception:
        # Full traceback to stderr + non-zero exit code so failures are
        # visible in logs and detected by whatever process manages the
        # connector's lifecycle (Docker, systemd, k8s, etc.).
        traceback.print_exc()
        exit(1)
