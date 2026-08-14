"""Connector persisted state.

The state is a small piece of data OpenCTI stores for the connector between
runs (in the platform's database). It is used to remember progress: the
last processed timestamp, the last page fetched, etc. This lets the
connector import only *new or updated* data on each run, instead of
re-importing everything from scratch every time.

Do not store large amounts of data here -- it is not a cache or a database,
only lightweight checkpoints needed to resume an import.
"""

from datetime import datetime

from connectors_sdk import ExternalImportConnectorState


class ConnectorState(ExternalImportConnectorState):
    """Checkpoints used to resume imports across connector runs.

    Overrides `ExternalImportConnectorState` (from `connectors-sdk`),
    which already provides a generic `last_run` timestamp, adding one
    field per processor that needs a more specific checkpoint.

    .. important::
        `last_report_update` and `vulnerabilities_current_page` below
        are a **worked example**, not required fields. They only exist to
        demonstrate the shape of a checkpoint field for the fictional
        `ReportsProcessor`/`VulnerabilitiesProcessor` (see
        `connector/data_processors/`). Neither is needed by
        `ExternalImportConnectorState` itself -- a connector state can
        have zero, one, or many such fields, entirely depending on what
        your own processors need to resume.

    TODO:
        - [ ] Delete `last_report_update`/`vulnerabilities_current_page`
          and add one field per processor that needs to resume (a
          timestamp, a page number, a cursor/token, an object id...).
          Some processors may not need any field at all if the
          inherited `last_run` is precise enough.
        - [ ] Keep field types simple (`str`, `int`, `datetime`,
          `None`) -- the state is serialized to JSON.
        - [ ] Give each field a default of `None` so a connector
          running for the first time starts from a clean state.
    """

    # EXAMPLE checkpoint for ReportsProcessor: timestamp of the last successfully
    # processed report. Delete/replace along with ReportsProcessor.
    last_report_update: datetime | None = None
    # EXAMPLE checkpoint for VulnerabilitiesProcessor: page to resume from if a
    # previous run was interrupted. Delete/replace along with VulnerabilitiesProcessor.
    vulnerabilities_current_page: int | None = None
