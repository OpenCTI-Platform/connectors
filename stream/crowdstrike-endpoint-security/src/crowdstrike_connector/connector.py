import json
from collections.abc import Callable

from connectors_sdk import DeploymentAssurance
from connectors_sdk.connectors.stream.deployment import PendingWithdrawals
from crowdstrike_connector.deployment import failure_reason
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
        self.pending_withdrawals = PendingWithdrawals(helper)
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
        - rejected by CrowdStrike: `failed` with the reason (the CrowdStrike error
          is logged)
        - unsupported IOC type or IOC absent from CrowdStrike (update): no report
        :param data: Indicator of the stream event
        :param operation: Client call
        :return: Outcome of the operation
        """
        try:
            result = operation()
        except Exception as err:
            if self.assurance is not None:
                self.assurance.report_push_failed(data, failure_reason(err))
            raise
        if result.status == IocOperationStatus.FAILED:
            self.helper.connector_logger.warning(
                "[PUSH] IOC not pushed to Crowdstrike",
                meta={
                    "indicator_id": data.get("id"),
                    "error": result.error,
                    "status_code": result.status_code,
                },
            )
        if self.assurance is not None:
            if result.is_live:
                self.assurance.report_pushed(data, external_id=result.ioc_id)
            elif result.status == IocOperationStatus.FAILED:
                self.assurance.report_push_failed(
                    data, failure_reason(result), external_id=result.ioc_id
                )
        return result

    def _withdraw_former_values(
        self, data: dict, values: list[str] | None = None
    ) -> Exception | None:
        """
        Withdraw the former IOC values of an indicator: those of the update being
        processed and those earlier updates could not withdraw, kept in the
        connector state (see `PendingWithdrawals`). A refusal is logged and the
        values left are kept for the next update or delete of the indicator
        :param data: Indicator of the stream event
        :param values: Former IOC values of the update being processed
        :return: The error of a refused withdrawal, None when no former value is left
        """
        indicator_id = data.get("id")
        try:
            self.pending_withdrawals.withdraw(
                indicator_id, self.client.withdraw_value, values or []
            )
        except Exception as err:
            self.helper.connector_logger.warning(
                "IOC of a former pattern not withdrawn from Crowdstrike",
                meta={
                    "indicator_id": indicator_id,
                    "ioc_values": self.pending_withdrawals.values(indicator_id),
                    "error": str(err),
                },
            )
            return err
        return None

    def _delete(self, data: dict) -> IocOperationResult:
        """
        Delete an IOC permanently and report `removed` once it is gone (deleted, or
        already absent from CrowdStrike) and no IOC of a former pattern is left
        :param data: Indicator of the stream event
        :return: Outcome of the operation
        """
        former_left = self._withdraw_former_values(data) is not None
        result = self.client.delete_indicator(data)
        if (
            self.assurance is not None
            and not former_left
            and result.status
            in (
                IocOperationStatus.DELETED,
                IocOperationStatus.ABSENT,
            )
        ):
            self.assurance.report_removed(data, external_id=result.ioc_id)
        elif result.status == IocOperationStatus.FAILED:
            self.helper.connector_logger.warning(
                "[DELETE] IOC not deleted from Crowdstrike",
                meta={"error": result.error},
            )
        return result

    def _former_value(self, data: dict, context: dict | None) -> str | None:
        """
        Return the IOC value an update event replaced, read from its reverse patch
        :param data: Indicator of the stream event, after the update
        :param context: Context of the update event
        :return: The former IOC value, None when the update kept the value or its
            former pattern holds none
        """
        for patch in (context or {}).get("reverse_patch") or []:
            if isinstance(patch, dict) and patch.get("path") == "/pattern":
                try:
                    former = self.client._extract_indicator_value(patch["value"])
                    current = self.client._extract_indicator_value(data["pattern"])
                except (AttributeError, IndexError, KeyError):
                    return None
                return former if former and former.lower() != current.lower() else None
        return None

    def _update(self, data: dict, former_value: str | None) -> None:
        """
        Apply an update event and report it
        IOCs are looked up by value: when the update changes the IOC value, the IOC
        of the former value would stay live. It is withdrawn first (as by the
        reconciliation), with the former values earlier updates could not withdraw,
        then the IOC of the current value is created and reported as for a create.
        A refused withdrawal is reported `failed` and the current value is not
        pushed; a current value CrowdStrike does not take is reported `removed`
        :param data: Indicator of the stream event, after the update
        :param former_value: IOC value of the pattern the update replaced, None when
            the update kept the value
        """
        error = self._withdraw_former_values(
            data, [former_value] if former_value else []
        )
        if error is not None:
            if self.assurance is not None:
                self.assurance.report_push_failed(data, failure_reason(error))
            return
        if former_value is None:
            self._push(data, lambda: self.client.update_indicator(data))
            return
        result = self._push(data, lambda: self.client.create_indicator(data, "create"))
        if result.status == IocOperationStatus.SKIPPED and self.assurance is not None:
            self.assurance.report_removed(data)

    def _process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        :param msg: Message event from stream
        :return: None
        """
        try:
            if self.metrics_enabled and self.metrics is not None:
                self.metrics.handle_metrics(msg)
            message = json.loads(msg.data)
            data = message["data"]
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
                self._update(data, self._former_value(data, message.get("context")))

            # Handle delete
            if msg.event == "delete":
                if self.config.crowdstrike.permanent_delete:
                    self.handle_logger_info("[DELETE]", data)
                    self._delete(data)
                else:
                    # The IOC is only tagged TO_DELETE and keeps detecting: no
                    # removal is reported (the reconciliation keeps it active)
                    self.handle_logger_info("[DELETE ON OPENCTI ONLY]", data)
                    self._withdraw_former_values(data)
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
