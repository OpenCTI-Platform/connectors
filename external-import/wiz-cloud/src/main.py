"""Entrypoint of the Wiz Cloud external import connector."""

import sys
import traceback

from connectors_sdk import ExternalImportConnector
from wiz_cloud import ConnectorSettings, WizConnectorState
from wiz_cloud.processors import WizIssuesProcessor, WizVulnerabilitiesProcessor
from wiz_cloud.run_context import WizRunContext

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        # Processors run sequentially in list order and share this context,
        # so the vulnerabilities processor sees the assets the issues
        # processor just imported.
        run_context = WizRunContext()
        processors = [WizIssuesProcessor(run_context=run_context)]
        if settings.wiz_cloud.import_vulnerabilities:
            processors.append(WizVulnerabilitiesProcessor(run_context=run_context))

        connector = ExternalImportConnector(
            settings=settings,
            data_processors=processors,
            state=WizConnectorState(),
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
