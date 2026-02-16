from datetime import UTC, datetime, timedelta

from lib.external_import import ExternalImportConnector
from pycti import OpenCTIConnectorHelper
from shadowserver.api import ShadowserverAPI
from shadowserver.settings import ConnectorSettings
from shadowserver.utils import remove_duplicates

LOOKBACK = 3
INITIAL_LOOKBACK = 30


class CustomConnector(ExternalImportConnector):

    def __init__(
        self, helper: OpenCTIConnectorHelper, config: ConnectorSettings
    ) -> None:
        """Initialization of the connector"""
        super().__init__(helper, config)
        self.first_run = True
        self.lookback = None
        if last_run := self.state.get("last_run"):
            last_run = (
                datetime.fromtimestamp(last_run, tz=UTC)
                if isinstance(last_run, float | int)
                else datetime.fromisoformat(last_run)
            )
            self.lookback = (self.start_time - last_run).days + LOOKBACK
            self.first_run = False
        else:
            self.lookback = INITIAL_LOOKBACK
        self.helper.connector_logger.info(
            f"Connector initialized. Lookback: {self.lookback} days. First run: {self.first_run}"
        )

    def _collect_intelligence(self) -> []:
        """Collects intelligence from channels

        Aadd your code depending on the use case as stated at https://docs.opencti.io/latest/development/connectors/.
        Some sample code is provided as a guide to add a specific observable and a reference to the main object.
        Consider adding additional methods to the class to make the code more readable.

        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.connector_logger.info(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        stix_objects = []
        shadowserver_api = ShadowserverAPI(
            api_key=self.config.shadowserver.api_key.get_secret_value(),
            api_secret=self.config.shadowserver.api_secret.get_secret_value(),
            marking_refs=self.config.shadowserver.marking,
        )
        subscription_list = shadowserver_api.get_subscriptions()
        self.helper.connector_logger.info(
            f"Available report types: {subscription_list}."
        )
        if not subscription_list:
            self.helper.connector_logger.error(
                "No report types found, please enable them following Shadowservers documentation. https://www.shadowserver.org/what-we-do/network-reporting/get-reports/"
            )
            raise ValueError(
                "No report types found, please enable them following Shadowservers documentation. https://www.shadowserver.org/what-we-do/network-reporting/get-reports/"
            )
        if subscription_list and isinstance(subscription_list, list):
            for subscription in subscription_list:
                for days_lookback in range(self.lookback, -1, -1):
                    date = self.start_time - timedelta(days=days_lookback)
                    date_str = date.strftime("%Y-%m-%d")
                    self.helper.connector_logger.info(
                        f"Getting ({subscription}) reports from ({date_str})."
                    )
                    report_list = shadowserver_api.get_report_list(
                        date=date_str, type=subscription
                    )
                    self.helper.connector_logger.debug(
                        f"Found {len(report_list)} reports."
                    )
                    for report in report_list:
                        report_stix_objects = shadowserver_api.get_stix_report(
                            report=report,
                            api_helper=self.helper,
                            incident={
                                "create": self.config.shadowserver.create_incident,
                                "severity": self.config.shadowserver.incident_severity,
                                "priority": self.config.shadowserver.incident_priority,
                            },
                        )
                        for stix_object in report_stix_objects:
                            if stix_object not in stix_objects and stix_object:
                                stix_objects.append(stix_object)
        self.helper.connector_logger.info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        unique_stix_objects = remove_duplicates(stix_objects)
        return unique_stix_objects
