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

UPDATE_ACTION = "IOC update"
"""What SentinelOne is asked to do when the pattern of an indicator changes."""


def failure_reason(error: SentinelOneApiError) -> str:
    """Return the reason OpenCTI shows for an indicator SentinelOne did not take.

    :param error: The error raised by the client.
    :return: One short sentence naming SentinelOne and the cause; the SentinelOne
        response is left to the logs.
    """
    return deployment_failure_reason(PLATFORM_NAME, PUSH_ACTION, error.status_code)


def _is_stix_indicator_id(value: Any) -> bool:
    """Whether a value is the STIX id of an indicator (the external id of its IOCs)."""
    return isinstance(value, str) and value.startswith(STIX_INDICATOR_PREFIX)


def _pattern_changed(context: Any) -> bool:
    """Whether an update event changed the pattern of the indicator.

    :param context: The context of the update event: its reverse patch holds the
        former value of every field the update changed.
    """
    reverse_patch = context.get("reverse_patch") if isinstance(context, dict) else None
    return isinstance(reverse_patch, list) and any(
        isinstance(patch, dict) and patch.get("path") == "/pattern"
        for patch in reverse_patch
    )


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
        of Stix Indicators and creates them in SentinelOne, for the update
        of their pattern to replace the IOCs created from them, and for their
        deletion to delete these IOCs

        :param msg: Message event from stream containing event data
        :return: None
        """
        try:
            message = json.loads(msg.data)
            data = message["data"]
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
            elif msg.event == "update" and _pattern_changed(message.get("context")):
                self._replace_and_report(data)
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
        :return: True when IOCs were deleted, False when none carries the indicator id
            (nothing is looked up for an id that is not a STIX indicator id).
        :raises SentinelOneApiError: When SentinelOne cannot list or delete the IOCs, or
            lists an IOC of the indicator without `uuid` (it could not be deleted).
        """
        stix_id = indicator.get("id")
        if not _is_stix_indicator_id(stix_id):
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
        once none is left in SentinelOne: deleted now, or already absent (the lookup
        completed without any IOC of the indicator), which also repairs a deployment
        no read-back can see (scope with a group).

        Nothing is reported for an id that is not a STIX indicator id, when the lookup
        or the deletion fails, or when nothing was found for a pattern SentinelOne does
        not support (never pushed, so it has no deployment).
        """
        if not _is_stix_indicator_id(data.get("id")):
            return
        try:
            deleted = self.delete_indicator(data)
        except SentinelOneApiError as err:
            self.helper.connector_logger.warning(
                "[DELETE] Failed to delete Indicator from SentinelOne",
                meta={"error": str(err)},
            )
            return
        if deleted:
            self.helper.connector_logger.info(
                "[DELETE] Successfully deleted Indicator from SentinelOne"
            )
        elif self.client.supports_pattern(data.get("pattern")):
            self.helper.connector_logger.info(
                "[DELETE] No IOC of the Indicator in SentinelOne, already removed",
                meta={"indicator_id": data.get("id")},
            )
        else:
            return
        if self.assurance is not None:
            self.assurance.report_removed(data)

    def _replace_and_report(self, data: dict[str, Any]) -> None:
        """
        Replace the IOCs of an indicator whose pattern changed: SentinelOne IOCs hold
        one value each, and no read-back repairs a scope with a group. The IOCs of the
        indicator are deleted, then the current pattern is created and reported like a
        create (`deployed` or `failed`).

        A failed deletion is reported `failed` (the former IOCs may remain). A pattern
        SentinelOne does not support is reported `removed` once the former IOCs are
        deleted, and not reported when none existed (never pushed, so it has no
        deployment). Nothing is done for an id that is not a STIX indicator id.
        """
        if not _is_stix_indicator_id(data.get("id")):
            return
        try:
            deleted = self.delete_indicator(data)
        except SentinelOneApiError as err:
            self.helper.connector_logger.warning(
                "[UPDATE] Failed to delete the former IOCs of the Indicator from "
                "SentinelOne",
                meta={"indicator_id": data.get("id"), "error": str(err)},
            )
            if self.assurance is not None:
                self.assurance.report_push_failed(
                    data,
                    deployment_failure_reason(
                        PLATFORM_NAME, UPDATE_ACTION, err.status_code
                    ),
                )
            return
        if not self.client.supports_pattern(data.get("pattern")):
            if deleted:
                self.helper.connector_logger.info(
                    "[UPDATE] Pattern no longer supported by SentinelOne, IOCs removed",
                    meta={"indicator_id": data.get("id")},
                )
                if self.assurance is not None:
                    self.assurance.report_removed(data)
            return
        self._create_and_report(data)

    def run(self) -> None:
        """
        Start the execution of the connector
        Anchored on the process_message method
        The deployment write-back (and its reconciliation) starts first.
        """
        if self.assurance is not None:
            self.assurance.start()
        self.helper.listen_stream(message_callback=self.process_message)
