import json
import logging
from typing import TYPE_CHECKING, Any

from connectors_sdk.connectors.stream.deployment import deployment_failure_reason
from pycti import OpenCTIConnectorHelper
from sentinelone_connector.settings import ConnectorSettings
from sentinelone_services import SentinelOneApiError, SentinelOneClient

if TYPE_CHECKING:
    from connectors_sdk import DeploymentAssurance

STIX_INDICATOR_PREFIX = "indicator--"

PLATFORM_NAME = "SentinelOne"
"""Name of the security platform in the deployment failure reasons."""

PUSH_ACTION = "IOC creation"
"""What SentinelOne is asked to do when an indicator is pushed."""


def failure_reason(error: SentinelOneApiError) -> str:
    """Return the reason OpenCTI shows for an indicator SentinelOne did not take.

    :param error: The error raised by the client.
    :return: One short sentence naming SentinelOne and the cause; the SentinelOne
        response is left to the logs.
    """
    return deployment_failure_reason(PLATFORM_NAME, PUSH_ACTION, error.status_code)


class SentinelOneIntelConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize the SentinelOne Intel Connector
        with necessary configurations

        `assurance` is the deployment write-back (dissemination assurance), set by `main.py`.
        """
        self.config = config
        self.helper = helper
        self.client = SentinelOneClient(config, helper)
        self.assurance: "DeploymentAssurance | None" = None

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works.
        Processes incoming steam messages and filters for the creation
        of Stix Indicators and creates them in SentinelOne, and for their
        deletion to delete the IOCs created from them

        :param msg: Message event from stream containing event data
        :return: None
        """
        try:
            data = json.loads(msg.data)["data"]
        except Exception as e:
            raise ValueError(f"Cannot process the message: {e}")

        # Handle the Creation of an Indicator with a stix pattern
        if data["type"] == "indicator" and data["pattern_type"] == "stix":
            if msg.event == "create":
                if self.helper.connector_logger.local_logger.isEnabledFor(logging.INFO):
                    # `get_attribute_in_extension` can take a while to execute,
                    # so we check if the logger is enabled for INFO level first
                    indicator_id = self.helper.get_attribute_in_extension("id", data)
                    self.helper.connector_logger.info(
                        "[CREATE] Processing indicator",
                        {"Indicator ID": indicator_id},
                    )
                self._create_and_report(data)
            elif msg.event == "delete":
                self._delete_and_report(data)

    def push_indicator(self, indicator: dict[str, Any]) -> str | None:
        """
        Create an OpenCTI indicator in SentinelOne (reconciliation re-push).

        :param indicator: The indicator, in the stream event shape.
        :return: The `uuid` of the first IOC created, if returned by SentinelOne.
        :raises ValueError: When the pattern of the indicator is not supported.
        :raises SentinelOneApiError: When SentinelOne rejects the indicator.
        """
        uuids = self.client.create_indicator(indicator)
        if uuids is None:
            raise ValueError(
                "The pattern of the indicator is not supported by SentinelOne"
            )
        return uuids[0] if uuids else None

    def delete_indicator(self, indicator: dict[str, Any]) -> bool:
        """
        Delete the IOCs created from an indicator: the IOCs of the scope of the connector
        whose external id is the STIX id of the indicator. IOCs created by other sources
        are never deleted.

        :param indicator: The indicator, in the stream event shape.
        :return: True when IOCs were deleted, False when none carries the indicator id.
        :raises SentinelOneApiError: When SentinelOne cannot list or delete the IOCs, or
            lists an IOC of the indicator without `uuid` (it could not be deleted).
        """
        stix_id = indicator.get("id")
        if not isinstance(stix_id, str) or not stix_id.startswith(
            STIX_INDICATOR_PREFIX
        ):
            return False
        iocs = [
            ioc
            for ioc in self.client.find_iocs_by_external_id(stix_id)
            if ioc.get("externalId") == stix_id
        ]
        if any(not isinstance(ioc.get("uuid"), str) or not ioc["uuid"] for ioc in iocs):
            raise SentinelOneApiError(
                "SentinelOne listed an IOC of the indicator without uuid, "
                "it cannot be deleted",
                status_code=200,
            )
        uuids = [str(ioc["uuid"]) for ioc in iocs]
        if not uuids:
            return False
        self.client.delete_iocs(uuids)
        return True

    def _create_and_report(self, data: dict[str, Any]) -> None:
        """
        Create the indicator of a create event and report the outcome to OpenCTI:
        `deployed` (with the `uuid` of the first IOC, if known) or `failed`; nothing
        is reported for an unsupported pattern.
        """
        try:
            uuids = self.client.create_indicator(data)
        except SentinelOneApiError as err:
            self.helper.connector_logger.warning(
                "[CREATE] Failed to create Indicator in SentinelOne",
                meta={"indicator_id": data.get("id"), "error": str(err)},
            )
            if self.assurance is not None:
                self.assurance.report_push_failed(data, failure_reason(err))
            return
        if uuids is None:
            return
        self.helper.connector_logger.info(
            "[CREATE] Successfully created Indicator in SentinelOne"
        )
        if self.assurance is not None:
            self.assurance.report_pushed(data, external_id=uuids[0] if uuids else None)

    def _delete_and_report(self, data: dict[str, Any]) -> None:
        """
        Delete the IOCs of the indicator of a delete event and report it `removed`
        when IOCs were deleted.
        """
        try:
            deleted = self.delete_indicator(data)
        except SentinelOneApiError as err:
            self.helper.connector_logger.warning(
                "[DELETE] Failed to delete Indicator from SentinelOne",
                meta={"error": str(err)},
            )
            return
        if not deleted:
            return
        self.helper.connector_logger.info(
            "[DELETE] Successfully deleted Indicator from SentinelOne"
        )
        if self.assurance is not None:
            self.assurance.report_removed(data)

    def run(self) -> None:
        """
        Start the execution of the connector
        Anchored on the process_message method
        The deployment write-back (and its reconciliation) starts first.
        """
        if self.assurance is not None:
            self.assurance.start()
        self.helper.listen_stream(message_callback=self.process_message)
