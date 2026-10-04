import json
from collections.abc import Callable

from connectors_sdk import DeploymentAssurance
from crowdstrike_connector.settings import ConnectorSettings
from crowdstrike_services import (
    CrowdstrikeClient,
    IocOperationResult,
    IocOperationStatus,
    Metrics,
)
from pycti import OpenCTIConnectorHelper


class CrowdstrikeConnector:
    """
    Crowdstrike Endpoint Security connector class
    """

    def __init__(
        self,
        config: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
        assurance: DeploymentAssurance | None = None,
    ) -> None:
        """
        Initialize the Crowdstrike Endpoint Security Connector
        with necessary configurations
        :param assurance: Deployment write-back (dissemination assurance), if any
        """
        self.config = config
        self.helper = helper
        self.client = CrowdstrikeClient(config.crowdstrike, helper)
        self.assurance = assurance
        self.metrics_enabled = config.metrics.enable
        self.metrics = None
        if self.metrics_enabled:
            self.metrics = Metrics(
                config.connector.name,
                str(config.metrics.addr),
                config.metrics.port,
            )

    def handle_logger_info(self, action: str, data: dict) -> None:
        """
        On action, update connector logger info
        :param action: Action in string
        :param data: Dict of data from stream
        :return: None
        """
        self.helper.connector_logger.info(
            f"{action} Processing indicator",
            {"Indicator ID": self.helper.get_attribute_in_extension("id", data)},
        )

    def _push(
        self, data: dict, operation: Callable[[], IocOperationResult]
    ) -> IocOperationResult:
        """
        Run a create or update operation and report its deployment outcome
        - live IOC (created, updated, already existing): `deployed` with the IOC id
        - rejected by CrowdStrike: `failed` with the CrowdStrike error
        - unsupported IOC type or IOC absent from CrowdStrike (update): no report
        :param data: Indicator of the stream event
        :param operation: Client call
        :return: Outcome of the operation
        """
        try:
            result = operation()
        except Exception as err:
            if self.assurance is not None:
                self.assurance.report_push_failed(data, err)
            raise
        if self.assurance is not None:
            if result.is_live:
                self.assurance.report_pushed(data, external_id=result.ioc_id)
            elif result.status == IocOperationStatus.FAILED:
                self.assurance.report_push_failed(
                    data,
                    result.error or "The CrowdStrike API rejected the IOC",
                    external_id=result.ioc_id,
                )
        return result

    def _delete(self, data: dict) -> IocOperationResult:
        """
        Delete an IOC permanently and report `removed` once it is gone
        (deleted, or already absent from CrowdStrike)
        :param data: Indicator of the stream event
        :return: Outcome of the operation
        """
        result = self.client.delete_indicator(data)
        if self.assurance is not None and result.status in (
            IocOperationStatus.DELETED,
            IocOperationStatus.ABSENT,
        ):
            self.assurance.report_removed(data, external_id=result.ioc_id)
        elif result.status == IocOperationStatus.FAILED:
            self.helper.connector_logger.warning(
                "[DELETE] IOC not deleted from Crowdstrike",
                meta={"error": result.error},
            )
        return result

    def _process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        :param msg: Message event from stream
        :return: None
        """
        try:
            if self.metrics_enabled and self.metrics is not None:
                self.metrics.handle_metrics(msg)
            data = json.loads(msg.data)["data"]
        except Exception:
            raise ValueError("Cannot process the message")

        # Extract data and handle only entity type 'Indicator' from stream
        if data["type"] == "indicator" and data["pattern_type"] in ["stix"]:
            self.helper.connector_logger.info(
                "Starting to extract data...", {"pattern_type": data["pattern_type"]}
            )

            # Handle creation
            if msg.event == "create":
                self.handle_logger_info("[CREATE]", data)
                self._push(data, lambda: self.client.create_indicator(data, msg.event))

            # Handle update
            if msg.event == "update":
                self.handle_logger_info("[UPDATE]", data)
                self._push(data, lambda: self.client.update_indicator(data))

            # Handle delete
            if msg.event == "delete":
                if self.config.crowdstrike.permanent_delete:
                    self.handle_logger_info("[DELETE]", data)
                    self._delete(data)
                else:
                    # The IOC is only tagged TO_DELETE and keeps detecting: no
                    # removal is reported (the reconciliation keeps it active)
                    self.handle_logger_info("[DELETE ON OPENCTI ONLY]", data)
                    self.client.update_indicator(data, msg.event)

    def run(self) -> None:
        """
        Start main execution loop procedure for connector
        """
        # Start getting metrics if metrics_enabled is true
        if self.metrics_enabled and self.metrics is not None:
            self.metrics.start_server()

        # Start the deployment write-back (reconciliation and hits included)
        if self.assurance is not None:
            self.assurance.start()

        # Start listening to the stream
        self.helper.listen_stream(self._process_message)
