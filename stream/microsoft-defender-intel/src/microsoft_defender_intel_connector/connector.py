import json
from json import JSONDecodeError

from connectors_sdk import DeploymentAssurance
from connectors_sdk.connectors.stream.deployment import (
    PendingWithdrawals,
    normalize_value,
    pattern_observable_values,
)
from microsoft_defender_intel_connector.api_handler import (
    DefenderApiHandler,
    DefenderApiHandlerError,
)
from microsoft_defender_intel_connector.deployment import (
    describe_error,
    failure_reason,
)
from microsoft_defender_intel_connector.settings import ConnectorSettings
from microsoft_defender_intel_connector.utils import (
    FILE_HASH_TYPES_MAPPER,
    IOC_TYPES,
    is_observable,
    is_stix_indicator,
)
from pycti import OpenCTIConnectorHelper


class MicrosoftDefenderIntelConnector:
    """
    Specifications of the Stream connector

    This class encapsulates the main actions, expected to be run by any stream connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector has the capability to listen to live streams from the OpenCTI platform.
    It is highly useful for creating connectors that can react and make decisions in real time.
    Actions on OpenCTI will apply the changes to the third-party connected platform
    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message

    """

    def __init__(
        self,
        config: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
        assurance: DeploymentAssurance | None = None,
    ):
        """
        Initialize the Connector with necessary configurations
        :param assurance: Deployment write-back (dissemination assurance), if any
        """
        self.config = config
        self.helper = helper
        self.assurance = assurance
        self.pending_withdrawals = PendingWithdrawals(helper)
        self.api = DefenderApiHandler(
            self.helper,
            base_url=self.config.microsoft_defender_intel.base_url,
            tenant_id=self.config.microsoft_defender_intel.tenant_id,
            client_id=self.config.microsoft_defender_intel.client_id,
            client_secret=self.config.microsoft_defender_intel.client_secret.get_secret_value(),
            resource_path=self.config.microsoft_defender_intel.resource_path,
            action=self.config.microsoft_defender_intel.action,
            expired_after=self.config.microsoft_defender_intel.expire_time,
        )

    def _check_stream_id(self) -> None:
        """
        In case of stream_id configuration is missing, raise Value Error
        :return: None
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _convert_indicator_to_observables(
        self, data, observable_values: list[dict] | None = None
    ) -> list[dict]:
        """
        Convert an OpenCTI indicator to its corresponding observables.
        Observables taken into account:
        :param data: OpenCTI indicator data
        :param observable_values: Observable values converted instead of the ones of the indicator
        :return: Observables data
        """
        try:
            observables = []
            parsed_observables = (
                observable_values
                if observable_values is not None
                else self.helper.get_attribute_in_extension("observable_values", data)
            )
            if parsed_observables:
                for observable in parsed_observables:
                    observable_data = {}
                    observable_data.update(data)
                    x_opencti_observable_type = observable.get("type").lower()
                    if x_opencti_observable_type != "stixfile":
                        observable_data["type"] = x_opencti_observable_type
                        observable_data["value"] = observable.get("value")
                        observables.append(observable_data)
                    else:
                        file = {}
                        for key, value in observable.get("hashes", {}).items():
                            hash_type = FILE_HASH_TYPES_MAPPER.get(key.lower())
                            if hash_type is not None:
                                file[hash_type] = value
                        if file:
                            observable_data["type"] = "file"
                            observable_data["hashes"] = file
                            observables.append(observable_data)
            return observables
        except:
            indicator_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                "id", data
            )
            self.helper.connector_logger.warning(
                "[CREATE] Cannot convert STIX indicator { " + indicator_opencti_id + "}"
            )

    def _create_defender_indicator(self, observable_data):
        """
        Create a Threat Intelligence Indicator on Defender from an OpenCTI observable.
        :param observable_data: OpenCTI observable data
        :return: True if the indicator has been successfully created, False otherwise
        """
        result = self.api.post_indicator(observable_data, None)
        if result:
            observable_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                "id", observable_data
            )
            self.helper.connector_logger.info(
                "[CREATE] Indicator created",
                {"defender_id": result["id"], "opencti_id": observable_opencti_id},
            )
            # The indicator is live in Defender: an OpenCTI error while linking the
            # external reference must not abort the dissemination.
            try:
                external_reference = self.helper.api.external_reference.create(
                    source_name="Microsoft Defender",
                    external_id=result["id"],
                    description="Intel within the Microsoft platform.",
                )
                if "pattern" in observable_data:
                    self.helper.api.stix_domain_object.add_external_reference(
                        id=observable_opencti_id,
                        external_reference_id=external_reference["id"],
                    )
                else:
                    self.helper.api.stix_cyber_observable.add_external_reference(
                        id=observable_opencti_id,
                        external_reference_id=external_reference["id"],
                    )
            except Exception as err:
                self.helper.connector_logger.warning(
                    "[CREATE] Cannot add the Microsoft Defender external reference",
                    meta={"defender_id": result["id"], "error": str(err)},
                )
        return result

    def _supported_observables(
        self, data: dict, observable_values: list[dict] | None = None
    ) -> list[dict]:
        """
        Return the observables of an OpenCTI indicator that Defender takes as indicators
        (IP addresses, domains, host names, URLs, files with an MD5, SHA-1 or SHA-256).
        :param data: OpenCTI indicator (stream event shape)
        :param observable_values: Observable values used instead of the ones of the indicator
        :return: The observables, one Defender indicator each
        """
        return [
            observable
            for observable in self._convert_indicator_to_observables(
                data, observable_values
            )
            or []
            if observable.get("type") == "file" or observable.get("type") in IOC_TYPES
        ]

    def _former_values(self, data: dict, context: dict | None) -> list[str]:
        """
        Return the values the connector pushed for the pattern an update replaced.
        The former pattern is read from the reverse patch of the update event: an
        update that does not change the pattern has none.
        :param data: OpenCTI indicator (stream event shape, after the update)
        :param context: Context of the update event
        :return: The Defender values of the former pattern
        """
        reverse_patch = (context or {}).get("reverse_patch") or []
        former_pattern = next(
            (
                patch.get("value")
                for patch in reverse_patch
                if isinstance(patch, dict) and patch.get("path") == "/pattern"
            ),
            None,
        )
        if not isinstance(former_pattern, str):
            return []
        return [
            value
            for observable in self._supported_observables(
                data, pattern_observable_values(former_pattern)
            )
            if (value := self._observable_value(observable))
        ]

    def _delete_former_value(
        self, opencti_id: str, value: str, indicators: list[dict] | None = None
    ) -> None:
        """
        Delete the Defender indicators of a former value of an OpenCTI indicator.
        :param opencti_id: OpenCTI id of the indicator (`externalId` of its Defender indicators)
        :param value: The former value
        :param indicators: Its Defender indicators, when already read
        :raise Exception: When Defender cannot be read or refuses a deletion
        """
        if indicators is None:
            indicators = self._own_defender_indicators(value, opencti_id)
        for indicator in indicators:
            defender_id = str(indicator["id"])
            self.api.delete_indicator(defender_id)
            self.helper.connector_logger.info(
                "[UPDATE] Indicator of a former value deleted",
                {"defender_id": defender_id, "opencti_id": opencti_id},
            )
            self._delete_external_reference(defender_id)

    def _withdraw_former_values(
        self,
        opencti_id: str | None,
        found: dict[str, list[dict]] | None = None,
        current_values: frozenset | set = frozenset(),
    ) -> bool:
        """
        Delete the Defender indicators of the values an updated indicator no longer holds,
        once its current values are live, and those earlier updates left (see
        `PendingWithdrawals`, keyed by the OpenCTI id the Defender indicators carry).
        A failure is logged and the values left are kept: the next update or delete of
        the indicator, or a periodic retry, deletes them.
        :param opencti_id: OpenCTI id of the indicator
        :param found: The Defender indicators of the former values of the update
            being processed, per value
        :param current_values: Normalized values of the current pattern, never deleted
        :return: True when no former value is left
        """
        if opencti_id is None:
            return True
        found = dict(found or {})

        def withdraw(value: str) -> None:
            if normalize_value(value) not in current_values:
                self._delete_former_value(opencti_id, value, found.pop(value, None))

        try:
            self.pending_withdrawals.withdraw(opencti_id, withdraw, list(found))
        except Exception as err:
            self.helper.connector_logger.warning(
                "[UPDATE] Cannot delete the Defender indicator of a former value",
                meta={
                    "opencti_id": opencti_id,
                    "values": self.pending_withdrawals.values(opencti_id),
                    "error": describe_error(err),
                },
            )
            return False
        return True

    @staticmethod
    def _observable_value(observable: dict) -> str | None:
        """Return the value Defender stores for an observable (one hash per file)."""
        if observable["type"] != "file":
            return observable["value"]
        for hash_type in ("sha256", "sha1", "md5"):
            if hash_type in observable["hashes"]:
                return observable["hashes"][hash_type]
        return None

    def _create_confirmed_defender_indicator(self, observable: dict) -> str:
        """
        Create the Defender indicator of an observable.
        :param observable: OpenCTI observable data
        :return: The Defender id
        :raise DefenderApiHandlerError: When Defender does not confirm the indicator
        """
        result = self._create_defender_indicator(observable)
        if not result or not result.get("id"):
            raise DefenderApiHandlerError(
                "[API] Microsoft Defender did not return the created indicator",
                {"value": self._observable_value(observable)},
            )
        return str(result["id"])

    def _roll_back_defender_indicators(self, defender_ids: list[str]) -> None:
        """
        Delete the Defender indicators created by a push that did not complete, so that
        no surviving indicator makes a partial deployment look live.
        :param defender_ids: Ids of the Defender indicators created by the push
        """
        for defender_id in defender_ids:
            try:
                self.api.delete_indicator(defender_id)
            except Exception as err:
                self.helper.connector_logger.warning(
                    "[CREATE] Cannot delete a Defender indicator of an incomplete push",
                    meta={"defender_id": defender_id, "error": str(err)},
                )
                continue
            self._delete_external_reference(defender_id)

    def _restore_defender_indicators(self, previous_indicators: list[dict]) -> None:
        """
        Write back the Defender indicators an update changed before it failed, so that
        Defender keeps the previous version of every observable instead of a mix that
        reconciliation would read as a complete deployment.
        :param previous_indicators: The indicators as Defender returned them before the update
        """
        for previous in previous_indicators:
            try:
                self.api.restore_indicator(previous)
            except Exception as err:
                self.helper.connector_logger.warning(
                    "[UPDATE] Cannot restore a Defender indicator of an incomplete update",
                    meta={"defender_id": previous.get("id"), "error": str(err)},
                )

    def push_indicator(self, data: dict) -> list[str]:
        """
        Create the Defender indicators of an OpenCTI indicator, one per observable.
        Shared by the stream create path and the reconciliation re-push. All or
        nothing: the indicators created by a push that fails are deleted again.
        :param data: OpenCTI indicator (stream event shape)
        :return: Ids of the Defender indicators created
        :raise DefenderApiHandlerError: When Defender rejects an indicator
        """
        defender_ids: list[str] = []
        try:
            for observable in self._supported_observables(data):
                defender_ids.append(
                    self._create_confirmed_defender_indicator(observable)
                )
        except Exception:
            self._roll_back_defender_indicators(defender_ids)
            raise
        return defender_ids

    def _report_failed(self, data: dict, error: BaseException) -> None:
        """Report an indicator rejected by Defender (no-op without write-back): OpenCTI
        gets a short reason, the Defender response goes to the log."""
        if self.assurance is not None:
            self.helper.connector_logger.warning(
                "Indicator not deployed on Microsoft Defender",
                meta={
                    "opencti_id": OpenCTIConnectorHelper.get_attribute_in_extension(
                        "id", data
                    ),
                    "error": describe_error(error),
                },
            )
            self.assurance.report_push_failed(data, failure_reason(error))

    def _report_pushed(self, data: dict, defender_ids: list[str]) -> None:
        """Report an indicator live in Defender, with its first Defender id."""
        if self.assurance is not None and defender_ids:
            self.assurance.report_pushed(data, external_id=defender_ids[0])

    def _update_defender_indicator(self, defender_id, observable_data) -> bool:
        """
        Update a Threat Intelligence Indicator on Defender from an OpenCTI observable.
        :param defender_id: Defender ID
        :param observable_data: OpenCTI observable data
        :return: True if the indicator has been successfully updated, False otherwise
        """
        self.api.post_indicator(observable_data, defender_id)
        return True

    def _handle_create_event(self, data):
        """
        Handle create event by trying to create the corresponding Threat Intelligence Indicator on Defender.
        :param data: Streamed data (representing either an observable or an indicator)
        """
        if is_stix_indicator(data):
            try:
                defender_ids = self.push_indicator(data)
            except Exception as err:
                self._report_failed(data, err)
                raise
            self._report_pushed(data, defender_ids)
        elif is_observable(data):
            self._create_defender_indicator(data)

    def _handle_update_event(self, data, context: dict | None = None):
        """
        Handle update event by trying to update the corresponding Threat Intelligence Indicator on Defender.
        The update holds the lock of the kept former values from its upsert to their
        deletion: a retry never deletes a value the update makes current again.
        :param data: Streamed data (representing either an observable or an indicator)
        :param context: Context of the update event (its reverse patch holds the former pattern)
        """
        with self.pending_withdrawals.lock:
            self._apply_update_event(data, context)

    def _apply_update_event(self, data, context: dict | None = None):
        """
        Update the Defender indicators of an indicator or an observable (see `_handle_update_event`).
        :param data: Streamed data (representing either an observable or an indicator)
        :param context: Context of the update event (its reverse patch holds the former pattern)
        """
        did_update = False
        opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        if is_stix_indicator(data):
            deployed_ids: list[str] = []
            created_ids: list[str] = []
            updated: list[dict] = []
            former: dict[str, dict] = {}
            former_found: dict[str, list[dict]] = {}
            current_values: set = set()
            try:
                observables = self._supported_observables(data)
                existing = [
                    (
                        observable,
                        self._own_defender_indicators(
                            self._observable_value(observable), opencti_id
                        ),
                    )
                    for observable in observables
                ]
                current_values = {
                    normalize_value(self._observable_value(observable))
                    for observable in observables
                }
                # The Defender indicators of the values the edited pattern no longer holds.
                for value in self._former_values(data, context):
                    if normalize_value(value) not in current_values:
                        former_found[value] = self._own_defender_indicators(
                            value, opencti_id
                        )
                        for indicator in former_found[value]:
                            former[str(indicator["id"])] = indicator
                # An indicator with at least one Defender indicator, for its current or
                # its former pattern, is deployed: every observable must have its own,
                # the missing ones are created.
                if former or any(found for _, found in existing):
                    for observable, found in existing:
                        if found:
                            defender_id = str(found[0]["id"])
                            self._update_defender_indicator(defender_id, observable)
                            updated.append(found[0])
                            message = "[UPDATE] Indicator updated"
                        else:
                            defender_id = self._create_confirmed_defender_indicator(
                                observable
                            )
                            created_ids.append(defender_id)
                            message = "[UPDATE] Missing indicator created"
                        deployed_ids.append(defender_id)
                        self.helper.connector_logger.info(
                            message,
                            meta={"defender_id": defender_id, "opencti_id": opencti_id},
                        )
                    did_update = True
            except Exception as err:
                # The former values stay on Defender with the previous version, until
                # the next update or delete of the indicator deletes them.
                self._restore_defender_indicators(updated)
                self._roll_back_defender_indicators(created_ids)
                if opencti_id is not None:
                    self.pending_withdrawals.keep(
                        opencti_id,
                        [value for value, found in former_found.items() if found],
                    )
                self._report_failed(data, err)
                raise
            left_by_earlier_updates = opencti_id is not None and bool(
                self.pending_withdrawals.values(opencti_id)
            )
            former_deleted = self._withdraw_former_values(
                opencti_id, former_found, current_values
            )
            if (
                (former or left_by_earlier_updates)
                and former_deleted
                and not deployed_ids
            ):
                # No value of the edited pattern is taken by Defender: none is left.
                if self.assurance is not None:
                    self.assurance.report_removed(data, external_id=None)
            self._report_pushed(data, deployed_ids)
        elif is_observable(data):
            result = self.api.find_indicators(data["value"])
            if len(result) > 0:
                self._update_defender_indicator(result[0]["id"], data)
                did_update = True
                self.helper.connector_logger.info(
                    "[UPDATE] Indicator updated",
                    {"defender_id": result[0]["id"], "opencti_id": opencti_id},
                )
        if not did_update:
            self.helper.connector_logger.info(
                "[UPDATE] Indicator not found on Microsoft Defender",
                {"opencti_id": opencti_id},
            )

    def _own_defender_indicators(self, value, opencti_id: str | None) -> list[dict]:
        """
        Return the Defender indicators of a value pushed for one OpenCTI indicator.
        Defender can hold the same value for another application or another OpenCTI
        indicator: only the indicators carrying its OpenCTI id as `externalId` are its own.
        :param value: Observable value
        :param opencti_id: OpenCTI id of the indicator
        :return: The Defender indicators of the value pushed for that indicator
        """
        if opencti_id is None:
            return []
        return [
            indicator
            for indicator in self.api.find_indicators(value) or []
            if (indicator.get("externalId") or indicator.get("externalID"))
            == opencti_id
        ]

    def _delete_external_reference(self, defender_id: str) -> None:
        """
        Delete the Microsoft Defender external reference of a deleted Defender indicator.
        An OpenCTI error is logged: the indicator is already removed from Defender.
        :param defender_id: Defender ID
        """
        try:
            external_reference = self.helper.api.external_reference.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "source_name", "values": ["Microsoft Defender"]},
                        {"key": "external_id", "values": [defender_id]},
                    ],
                    "filterGroups": [],
                }
            )
            if external_reference is not None:
                self.helper.api.external_reference.delete(external_reference["id"])
        except Exception as err:
            self.helper.connector_logger.warning(
                "[DELETE] Cannot delete the Microsoft Defender external reference",
                meta={"defender_id": defender_id, "error": str(err)},
            )

    def _handle_delete_event(self, data):
        """
        Handle delete event by trying to delete the corresponding Threat Intelligence Indicators on Defender.
        :param data: Streamed data (representing either an observable or an indicator)
        """
        did_delete = False
        opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        if is_stix_indicator(data):
            former_left = not self._withdraw_former_values(opencti_id)
            observables = self._convert_indicator_to_observables(data) or []
            deleted_ids = []
            for observable in observables:
                observable_value = None
                if observable["type"] == "file":
                    if "sha256" in observable["hashes"]:
                        observable_value = observable["hashes"]["sha256"]
                    elif "sha1" in observable["hashes"]:
                        observable_value = observable["hashes"]["sha1"]
                    elif "md5" in observable["hashes"]:
                        observable_value = observable["hashes"]["md5"]
                else:
                    observable_value = observable["value"]
                result = self._own_defender_indicators(observable_value, opencti_id)
                for indicator_result in result:
                    self.api.delete_indicator(indicator_result["id"])
                    did_delete = True
                    deleted_ids.append(str(indicator_result["id"]))
                    self.helper.connector_logger.info(
                        "[DELETE] Indicator deleted",
                        {
                            "defender_id": indicator_result["id"],
                            "opencti_id": opencti_id,
                        },
                    )
                    self._delete_external_reference(indicator_result["id"])
            if self.assurance is not None and not former_left:
                # Also when no Defender indicator was found: it is absent from Defender
                self.assurance.report_removed(
                    data, external_id=deleted_ids[0] if deleted_ids else None
                )
        elif is_observable(data):
            result = self.api.find_indicators(data["value"])
            for indicator_result in result:
                self.api.delete_indicator(indicator_result["id"])
                did_delete = True
                self.helper.connector_logger.info(
                    "[DELETE] Indicator deleted",
                    {"defender_id": indicator_result["id"], "opencti_id": opencti_id},
                )
                self._delete_external_reference(indicator_result["id"])
        if not did_delete:
            self.helper.connector_logger.info(
                "[DELETE] Indicator not found on Microsoft Defender",
                {"opencti_id": opencti_id},
            )

    def validate_json(self, msg) -> dict | JSONDecodeError:
        """
        Validate the JSON data from the stream
        :param msg: Message event from stream
        :return: Parsed JSON data or raise JSONDecodeError if JSON data cannot be parsed
        """
        try:
            parsed_msg = json.loads(msg.data)
            return parsed_msg
        except json.JSONDecodeError:
            self.helper.connector_logger.error(
                "Data cannot be parsed to JSON", {"msg_data": msg.data}
            )
            raise JSONDecodeError("Data cannot be parsed to JSON", msg.data, 0)

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        :return: string
        """
        try:
            self._check_stream_id()
            parsed_msg = self.validate_json(msg)
            data = parsed_msg["data"]
            if msg.event == "create":
                self._handle_create_event(data)
            if msg.event == "update":
                self._handle_update_event(data, parsed_msg.get("context"))
            if msg.event == "delete":
                self._handle_delete_event(data)
        except DefenderApiHandlerError as err:
            self.helper.connector_logger.error(err.msg, err.metadata)
        except Exception as err:
            self.helper.connector_logger.error(
                "Failed processing data {" + str(err) + "}"
            )
            self.helper.connector_logger.error("Message data {" + str(msg) + "}")
        finally:
            return None

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        if self.assurance is not None:
            self.assurance.start()
        # Former values whose Defender indicators could not be deleted are retried,
        # also once the indicator is deleted.
        self.pending_withdrawals.start_retries(self._delete_former_value)
        self.helper.listen_stream(message_callback=self.process_message)
