from __future__ import annotations

from pycti import OpenCTIConnectorHelper

from connector.import_filter import parse_iso_duration
from connector.import_runner import ImportRunner
from connector.settings import ConnectorSettings
from connector.stairwell import StairwellClient


class StairwellImportConnector:
    """External-import connector: periodically pulls Stairwell MalEval indicators.

    Scheduling and work registration are owned by the OpenCTI connector helper:
    `run()` registers `process_message` with `schedule_process`, and each run
    opens a work item (`initiate_work` / `to_processed`) so the ingestion shows
    up in the OpenCTI work log.
    """

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper

        s = config.stairwell
        self.client = StairwellClient(
            api_token=s.api_token,
            base_url=str(s.api_base_url),
            organization_id=s.organization_id or None,
            user_id=s.user_id or None,
        )
        self.runner = ImportRunner(
            helper=helper,
            client=self.client,
            first_run_window=parse_iso_duration(s.import_first_run_window),
            max_indicators=s.import_max_indicators,
            page_size=s.import_page_size,
            min_bucket=s.import_min_bucket,
            scope_environment=(s.import_scope.lower() == "environment"),
            wrapper=s.import_wrapper,
            tlp=s.import_tlp,
            indicator_validity_days=s.import_indicator_validity_days,
        )

    def process_message(self) -> None:
        friendly_name = "Stairwell import"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        try:
            message = self.runner.run(work_id=work_id)
        except Exception as err:  # noqa: BLE001
            self.helper.connector_logger.error(
                "[CONNECTOR] Stairwell import run failed",
                {"error": str(err)},
            )
            message = f"Run failed: {err}"
        self.helper.api.work.to_processed(work_id, message)
        self.helper.connector_logger.info(
            "[CONNECTOR] Stairwell import run finished", {"message": message}
        )

    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
