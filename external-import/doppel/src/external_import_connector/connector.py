from .client_api import ConnectorClient
from .converter_to_stix import ConverterToStix
from .utils import get_last_run, set_last_run


class DoppelConnector:
    def __init__(self, config, helper):
        self.helper = helper
        self.config = config
        self.client = ConnectorClient(self.helper, self.config)
        self.converter = ConverterToStix(self.helper, self.config)

    def _collect_alerts(self):
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

    def process_message(self):
        self.helper.connector_logger.info("[DoppelConnector] Running scheduled fetch")

        try:
            alerts = self._collect_alerts()
            if alerts:
                bundle = self.converter.convert_alerts_to_stix(alerts)
                bundle_sent = self.helper.send_stix2_bundle(bundle)
                self.helper.connector_logger.info(
                    "STIX bundle sent", {"objects": len(bundle_sent)}
                )
                set_last_run(self.helper)
        except Exception as err:
            self.helper.connector_logger.error(
                f"[DoppelConnector] Error in process_message: {str(err)}"
            )
            raise

    def run(self):
        self.helper.connector_logger.info("[DoppelConnector] Starting scheduler")
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
