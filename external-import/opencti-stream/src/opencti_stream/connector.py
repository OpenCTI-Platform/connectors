import json
import sys

from opencti_stream.settings import ConnectorSettings
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class OpenCTIStream:
    """Forward events from an OpenCTI live stream as STIX 2.1 bundles.

    For each create/update event received on the configured live stream, a one-object
    STIX 2.1 bundle is built and dispatched via `helper.send_stix2_bundle()`. The output
    destination (RabbitMQ queue, local directory or S3 bucket) is controlled by the
    standard connector helper settings (`CONNECTOR_SEND_TO_*`).

    The originating user (`origin.user_id` of each stream event) is propagated as the
    bundle's `applicant_id`, so identity attribution is preserved both for in-platform
    queue ingestion and across a diode boundary when paired with the `diode-import`
    connector on the target instance.
    """

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper

    def _process_message(self, msg) -> None:
        if msg.event not in ("create", "update"):
            return
        try:
            payload = json.loads(msg.data)
        except json.JSONDecodeError as exc:
            self.helper.connector_logger.warning(
                "Skipping malformed stream message",
                {"event_id": msg.id, "error": str(exc)},
            )
            return

        stix_object = payload.get("data")
        if not isinstance(stix_object, dict):
            return

        # Carry the originating user as the bundle applicant. Persisted into the bundle
        # in directory/S3 mode (used by `diode-import` for applicant remapping via
        # `DIODE_IMPORT_APPLICANT_MAPPINGS`) and into the queue message in queue mode
        # (used by workers for impersonation).
        origin_user_id = (payload.get("origin") or {}).get("user_id")
        if origin_user_id:
            self.helper.applicant_id = origin_user_id

        bundle = self.helper.stix2_create_bundle([stix_object])
        self.helper.send_stix2_bundle(bundle, no_split=True)
        self.helper.connector_logger.debug(
            "Forwarded stream event",
            {
                "event_id": msg.id,
                "stix_id": stix_object.get("id"),
                "applicant_id": origin_user_id,
            },
        )

    def run(self) -> None:
        try:
            self.helper.listen_stream(self._process_message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("OpenCTI Stream connector stopping...")
            sys.exit(0)
