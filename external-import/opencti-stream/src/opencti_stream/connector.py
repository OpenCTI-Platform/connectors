import json
import sys
from datetime import datetime, timezone

from opencti_stream.settings import ConnectorSettings
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class OpenCTIStream:
    """Forward events from an OpenCTI live stream as STIX 2.1 bundles.

    For each create/update event received on the configured live stream, a one-object
    STIX 2.1 bundle is built and dispatched via `helper.send_stix2_bundle()`. The output
    destination (RabbitMQ queue, local directory or S3 bucket) is controlled by the
    standard connector helper settings (`CONNECTOR_SEND_TO_*`).

    Identity attribution is preserved end-to-end:
    - The originating user (`origin.user_id` of each stream event) is propagated as
      the bundle's `applicant_id`, used by workers in queue mode and by `diode-import`
      via `DIODE_IMPORT_APPLICANT_MAPPINGS` in directory / S3 modes.
    - The forwarded objects are NOT mutated. In particular, `created_by_ref` is left
      untouched so the original source attribution carries over to the target instance.

    Runtime model:
    - The SSE consumer is a long-lived background thread started by
      `helper.listen_stream`. It is supervised by `helper.schedule_process`, which
      acts as a periodic watchdog: every `duration_period`, the connector verifies
      that the thread is alive and restarts it if it has died. Each (re)start is
      tracked as a Work in OpenCTI for visibility.
    """

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper
        self._stream_thread = None

    def _on_event(self, msg) -> None:
        """SSE callback: forward one stream event as a one-object STIX bundle."""
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
        self.helper.send_stix2_bundle(
            bundle,
            no_split=True,
            cleanup_inconsistent_bundle=True,
        )
        self.helper.connector_logger.debug(
            "Forwarded stream event",
            {
                "event_id": msg.id,
                "stix_id": stix_object.get("id"),
                "applicant_id": origin_user_id,
            },
        )

    def process_message(self) -> None:
        """Watchdog scheduled by `helper.schedule_process`.

        Starts the SSE consumer thread on the first invocation; on subsequent
        invocations it is a no-op as long as the thread is alive, and re-starts
        it otherwise. Each (re)start is wrapped in an OpenCTI Work for tracking.
        """
        if self._stream_thread is not None and self._stream_thread.is_alive():
            self.helper.connector_logger.debug(
                "SSE consumer alive, skipping scheduled run"
            )
            return

        friendly_name = "OpenCTI Stream session @ " + datetime.now(
            tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S")
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        try:
            # Pass an explicit URL stripped of any trailing slash. `helper.opencti_url`
            # is normalized by pydantic's `HttpUrl` to always end with "/", and pycti's
            # `listen_stream` concatenates "/stream" directly, which would produce a
            # double slash in the SSE URL. Stripping here keeps the URL clean.
            self._stream_thread = self.helper.listen_stream(
                self._on_event,
                url=self.helper.opencti_url.rstrip("/"),
            )
            self.helper.api.work.to_processed(work_id, "SSE consumer started")
            self.helper.connector_logger.info(
                "SSE consumer started", {"work_id": work_id}
            )
        except Exception as exc:
            self.helper.api.work.to_processed(work_id, str(exc), in_error=True)
            raise

    def run(self) -> None:
        try:
            self.helper.schedule_process(
                message_callback=self.process_message,
                duration_period=self.config.connector.duration_period.total_seconds(),
            )
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("OpenCTI Stream connector stopping...")
            sys.exit(0)
