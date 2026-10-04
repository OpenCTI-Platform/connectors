import json
import sys
import traceback

from connectors_sdk import DeploymentAssurance
from filigran_sseclient.sseclient import Event
from microsoft_sentinel_intel.client import ConnectorClient
from microsoft_sentinel_intel.errors import (
    ConnectorClientError,
    ConnectorError,
    ConnectorWarning,
)
from microsoft_sentinel_intel.settings import ConnectorSettings
from microsoft_sentinel_intel.utils import (
    describe_error,
    is_stix_identity,
    is_stix_indicator,
)
from pycti import OpenCTIConnectorHelper

REJECTED_UPLOAD_MESSAGE = "[API] Microsoft Sentinel rejected the object"


def _rejected_objects(response: object, count: int) -> dict[int, str]:
    """Return the reason of each object an upload response rejected, by index.

    Sentinel answers 200 when at least one object is imported and lists the rejected
    ones in `errors` (`recordIndex`, `errorMessages`). An error that names no object
    of the upload rejects all of them: a rejected object is never reported live.

    :param response: The upload response.
    :param count: The number of objects uploaded.
    :return: The rejection reason by object index (empty when all were imported).
    """
    try:
        body = json.loads(response.body())
    except (AttributeError, TypeError, ValueError):
        return {}
    errors = body.get("errors") if isinstance(body, dict) else None
    if not errors:
        return {}
    rejected: dict[int, str] = {}
    for entry in errors if isinstance(errors, list) else [errors]:
        error = entry if isinstance(entry, dict) else {}
        messages = error.get("errorMessages")
        reason = (
            "; ".join(str(message) for message in messages)
            if isinstance(messages, list) and messages
            else "rejected by Microsoft Sentinel"
        )
        index = error.get("recordIndex")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index < count
        ):
            return dict.fromkeys(range(count), reason)
        rejected[index] = reason
    return rejected


class Connector:

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: ConnectorSettings,
        client: ConnectorClient,
        assurance: DeploymentAssurance | None = None,
    ) -> None:
        self.helper = helper
        self.config = config
        self.client = client
        # Deployment write-back (dissemination assurance), wired by `main.py`.
        self.assurance = assurance

    def _prepare_stix_object(self, stix_object: dict) -> dict:
        stix_object = dict(stix_object)
        if self.config.microsoft_sentinel_intel.delete_extensions:
            stix_object.pop("extensions", None)
        if extra_labels := self.config.microsoft_sentinel_intel.extra_labels:
            stix_object["labels"] = list(
                set(stix_object.get("labels", []) + extra_labels)
            )
        return stix_object

    def _is_supported_stix_object(self, data: dict) -> bool:
        """Check whether a STIX object should be processed by this connector.

        Indicators are always supported. STIX Identity objects (e.g. an
        indicator's author) are supported only when the
        `publish_identities` config option is enabled.

        :param data: STIX object data dict.
        :return: True if the object should be processed, False otherwise.
        """
        if is_stix_indicator(data):
            return True
        if (
            self.config.microsoft_sentinel_intel.publish_identities
            and is_stix_identity(data)
        ):
            return True
        return False

    def push_indicator(self, stix_object: dict) -> None:
        """Upload one STIX object to Microsoft Sentinel.

        Shared by the stream create/update path and the reconciliation re-push.

        :param stix_object: STIX object data dict (stream event shape).
        :raises ConnectorClientError: If the upload API rejects the object (also
            when it answers 200 with the object in its `errors`).
        """
        response = self.client.upload_stix_objects(
            stix_objects=[self._prepare_stix_object(stix_object)],
            source_system=self.config.microsoft_sentinel_intel.source_system,
        )
        if rejected := _rejected_objects(response, 1):
            raise ConnectorClientError(
                message=REJECTED_UPLOAD_MESSAGE, metadata={"error": rejected[0]}
            )

    def _report_uploaded(self, stix_objects: list[dict]) -> None:
        """Report the indicators accepted by the upload API.

        A revoked indicator uploaded to Sentinel is no longer valid there (revocation
        propagated), so it is reported `removed`; others are reported `deployed`.
        Sentinel returns no per-object id: the indicator keeps its STIX id.
        """
        if self.assurance is None:
            return
        for stix_object in stix_objects:
            if not is_stix_indicator(stix_object):
                continue
            if stix_object.get("revoked") is True:
                self.assurance.report_removed(stix_object)
            else:
                self.assurance.report_pushed(stix_object)

    def _report_upload_failed(
        self, stix_objects: list[dict], error: BaseException
    ) -> None:
        """Report the indicators rejected by the upload API."""
        if self.assurance is None:
            return
        message = describe_error(error)
        for stix_object in stix_objects:
            if is_stix_indicator(stix_object):
                self.assurance.report_push_failed(stix_object, message)

    def _report_deleted(self, stix_object: dict) -> None:
        """Report an indicator removed from Sentinel (or already absent)."""
        if self.assurance is not None:
            self.assurance.report_removed(stix_object)

    def _process_event(self, event_type: str, stix_object: dict) -> bool:
        """Process a single STIX event by dispatching to the appropriate API call.

        The upload API (upload_stix_objects) handles Indicators, AttackPatterns,
        Identity, ThreatActors, and Relationships.

        :param event_type: One of "create", "update", or "delete".
        :param stix_object: STIX object data dict.
        :return: True if the event was processed, False if filtered out by event_types config.
        :raises ConnectorClientError: If the API call fails.
        :raises ConnectorWarning: If event_type is unsupported.
        """
        if event_type not in self.config.microsoft_sentinel_intel.event_types:
            self.helper.connector_logger.info(
                message=f"[{event_type.upper()}] Event type filtered out, skipping"
            )
            return False

        match event_type:
            case "create" | "update":
                try:
                    self.push_indicator(stix_object)
                except Exception as err:
                    self._report_upload_failed([stix_object], err)
                    raise
                self._report_uploaded([stix_object])
            case "delete":
                if not is_stix_indicator(stix_object):
                    self.helper.connector_logger.info(
                        message=f"[{event_type.upper()}] Skipping delete: only STIX indicators are supported for this operation",
                        meta={
                            "opencti_id": stix_object.get("id"),
                            "type": stix_object.get("type"),
                        },
                    )
                    return False
                self.client.delete_indicator_by_id(
                    stix_object["id"],
                    source_system=self.config.microsoft_sentinel_intel.source_system,
                )
                self._report_deleted(stix_object)
            case _:
                raise ConnectorWarning(
                    message=f"Unsupported event type: {event_type}, Skipping..."
                )
        return True

    def _handle_event(self, event: Event):
        try:
            parsed = json.loads(event.data)
        except json.JSONDecodeError as err:
            raise ConnectorError(
                message="[ERROR] Data cannot be parsed to JSON",
                metadata={"message_data": event.data, "error": str(err)},
            ) from err

        data = parsed.get("data")
        if not data:
            return

        if self._is_supported_stix_object(data):
            self.helper.connector_logger.info(
                message=f"[{event.event.upper()}] Processing message",
                meta={"data": data, "event": event.event},
            )
            processed = self._process_event(event_type=event.event, stix_object=data)
            if processed:
                self.helper.connector_logger.info(
                    message=f"[{event.event.upper()}] {data.get('type', 'Object').capitalize()} processed",
                    meta={"opencti_id": data["id"]},
                )
        else:
            self.helper.connector_logger.info(
                message=f"[{event.event.upper()}] Entity not supported"
            )

    def process_message(self, message: Event) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param message: Message event from stream
        :return: string
        """
        try:
            self._handle_event(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped by user.")
            sys.exit(0)
        except ConnectorWarning as err:
            self.helper.connector_logger.warning(message=err.message)
        except ConnectorError as err:
            self.helper.connector_logger.error(message=err.message, meta=err.metadata)
        except Exception as err:
            traceback.print_exc()
            self.helper.connector_logger.error(
                message=f"Unexpected error: {err}", meta={"error": str(err)}
            )

    def process_batch(self, batch_data: dict) -> None:
        """
        Batch callback for SDK BatchCallbackWrapper.
        Receives a dict with "events" (list of raw SSE messages) and processes them
        as a single batch upload.
        """
        try:
            events = batch_data.get("events", [])
            if not events:
                return

            unique_objects: dict[str, tuple[str, dict]] = {}
            for event in events:
                try:
                    parsed = json.loads(event.data)
                except json.JSONDecodeError as err:
                    self.helper.connector_logger.error(
                        message="[BATCH] Data cannot be parsed to JSON",
                        meta={"message_data": event.data, "error": str(err)},
                    )
                    continue

                data = parsed.get("data")
                if not data:
                    continue

                if not self._is_supported_stix_object(data):
                    continue

                if event.event not in self.config.microsoft_sentinel_intel.event_types:
                    continue

                unique_objects[data["id"]] = (event.event, data)

            if not unique_objects:
                return

            objects_to_upload = []
            objects_to_delete = []
            for event_type, data in unique_objects.values():
                if event_type in ("create", "update"):
                    objects_to_upload.append(data)
                elif event_type == "delete" and is_stix_indicator(data):
                    objects_to_delete.append(data)

            if objects_to_upload:
                prepared_objects = [
                    self._prepare_stix_object(obj) for obj in objects_to_upload
                ]
                self.helper.connector_logger.info(
                    message=f"[BATCH] Uploading {len(prepared_objects)} objects",
                )
                try:
                    response = self.client.upload_stix_objects(
                        stix_objects=prepared_objects,
                        source_system=self.config.microsoft_sentinel_intel.source_system,
                    )
                except Exception as err:
                    self._report_upload_failed(objects_to_upload, err)
                    raise
                rejected = _rejected_objects(response, len(objects_to_upload))
                if rejected:
                    self.helper.connector_logger.warning(
                        message=f"[BATCH] Microsoft Sentinel rejected {len(rejected)}/{len(objects_to_upload)} objects",
                        meta={"errors": sorted(set(rejected.values()))},
                    )
                self._report_uploaded(
                    [
                        data
                        for index, data in enumerate(objects_to_upload)
                        if index not in rejected
                    ]
                )
                for index in sorted(rejected):
                    self._report_upload_failed(
                        [objects_to_upload[index]],
                        ConnectorClientError(
                            message=REJECTED_UPLOAD_MESSAGE,
                            metadata={"error": rejected[index]},
                        ),
                    )

            for data in objects_to_delete:
                try:
                    self.helper.connector_logger.info(
                        message="[BATCH] Deleting indicator",
                        meta={"opencti_id": data["id"]},
                    )
                    self.client.delete_indicator_by_id(
                        data["id"],
                        source_system=self.config.microsoft_sentinel_intel.source_system,
                    )
                    self._report_deleted(data)
                except ConnectorClientError as err:
                    self.helper.connector_logger.error(
                        message=f"[BATCH] Failed to delete indicator {data['id']}",
                        meta=err.metadata,
                    )
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped by user.")
            sys.exit(0)
        except ConnectorWarning as err:
            self.helper.connector_logger.warning(message=err.message)
        except ConnectorError as err:
            self.helper.connector_logger.error(message=err.message, meta=err.metadata)
        except Exception as err:
            traceback.print_exc()
            self.helper.connector_logger.error(
                message=f"[BATCH] Unexpected error: {err}",
                meta={"error": str(err)},
            )

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        if self.assurance is not None:
            self.assurance.start()
        if self.config.microsoft_sentinel_intel.batch_mode:
            self.helper.connector_logger.info(
                message=f"[BATCH] Batch mode enabled (batch_size={self.config.microsoft_sentinel_intel.batch_size}, batch_timeout={self.config.microsoft_sentinel_intel.batch_timeout}s, max_per_minute=100)",
            )
            callback = self.helper.create_batch_callback(
                batch_callback=self.process_batch,
                batch_size=self.config.microsoft_sentinel_intel.batch_size,
                batch_timeout=self.config.microsoft_sentinel_intel.batch_timeout,
                # Azure Sentinel Upload Indicators API is limited to 100 requests/min
                max_per_minute=100,
            )
            self.helper.listen_stream(message_callback=callback)
        else:
            self.helper.listen_stream(message_callback=self.process_message)
