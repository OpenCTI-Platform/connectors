from .client_api import ConnectorClient
from .converter_to_stix import ConverterToStix
from .utils import get_last_run, set_last_run


class DoppelConnector:
    def __init__(self, config, helper):
        """
        Initialize the Connector with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.client = ConnectorClient(self.helper, self.config)
        self.converter = ConverterToStix(self.helper, self.config)

    def _collect_alerts(self) -> list:
        """
        Collect alerts from the source and convert into STIX object
        :return: List of alerts from response.json()
        """
        last_timestamp = get_last_run(self.helper, self.config.historical_days)

        all_alerts = []
        page = 0
        while True:
            response = self.client.get_alerts(last_timestamp, page)
            if not response:
                break

            alerts = response.json().get("alerts", [])
            if not alerts:
                break

            all_alerts.extend(alerts)
            page += 1

        self.helper.connector_logger.info("Fetched alerts", {"count": len(all_alerts)})
        return all_alerts

    def process_message(self) -> None:
        """
        Connector main process to collect alerts
        :return: None
        """
        self.helper.connector_logger.info("[DoppelConnector] Running scheduled fetch")

        try:
            alerts = self._collect_alerts()
            if alerts:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, "Connector feed"
                )

                bundle = self.converter.convert_alerts_to_stix(alerts)

                bundle_sent = self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=True
                )

                self.helper.connector_logger.info(
                    "STIX bundle sent", {"objects": len(bundle_sent)}
                )

                set_last_run(self.helper)

                self.helper.api.work.to_processed(
                    work_id, f"{self.helper.connect_name} connector successfully run"
                )

                work_id = None
        except Exception as err:
            self.helper.connector_logger.error(
                "[DoppelConnector] Error in process_message", {"error": err}
            )
            raise

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.connector_logger.info("[DoppelConnector] Starting scheduler")
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
