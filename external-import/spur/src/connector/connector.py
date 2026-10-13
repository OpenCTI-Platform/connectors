import sys
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from spur_client import SpurClient


class SpurConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = SpurClient(
            helper=self.helper,
            api_key=self.config.spur.api_key,
        )
        self.converter = ConverterToStix(
            helper=self.helper,
            config=self.config.spur,
        )

    def _flush_batch(self, batch: list, work_id: str) -> None:
        if not batch:
            return
        stix_header = [self.converter.author, self.converter.tlp_marking]
        bundle = self.helper.stix2_create_bundle(stix_header + batch)
        self.helper.send_stix2_bundle(
            bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )

    def _collect_intelligence(self, work_id: str) -> None:
        batch: list = []
        record_count = 0

        for feed_url in self.config.spur.feed_urls:
            self.helper.connector_logger.info(
                "[SPUR] Processing feed", meta={"url": feed_url}
            )
            for record in self.client.stream_feed(feed_url):
                objects = self.converter.convert_ip_context(record)
                batch.extend(objects)
                record_count += 1

                if record_count % self.config.spur.batch_size == 0:
                    self._flush_batch(batch, work_id)
                    batch = []
                    self.helper.connector_logger.info(
                        "[SPUR] Flushed batch",
                        meta={"records_processed": record_count},
                    )

        self._flush_batch(batch, work_id)
        self.helper.connector_logger.info(
            "[SPUR] Feed import complete", meta={"total_records": record_count}
        )

    def process_message(self) -> None:
        self.helper.connector_logger.info(
            "[SPUR] Starting connector run",
            meta={"connector_name": self.helper.connect_name},
        )

        try:
            now = datetime.now(tz=timezone.utc)
            current_state = self.helper.get_state() or {}

            if "last_run" in current_state:
                self.helper.connector_logger.info(
                    "[SPUR] Last run", meta={"last_run": current_state["last_run"]}
                )
            else:
                self.helper.connector_logger.info("[SPUR] First run")

            friendly_name = f"Spur feed @ {now.strftime('%Y-%m-%d %H:%M:%S')} UTC"
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self._collect_intelligence(work_id)

            current_state["last_run"] = now.isoformat()
            self.helper.set_state(current_state)

            message = f"Spur feed import complete at {now.isoformat()}"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[SPUR] Connector stopped")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(
                "[SPUR] Connector error", meta={"error": str(err)}
            )
            raise

    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
