import datetime
import sys
import traceback
from typing import Any

import stix2
from pycti import OpenCTIConnectorHelper

from microsoft_defender_threat_intel.client import ConnectorClient
from microsoft_defender_threat_intel.config import ConnectorSettings
from microsoft_defender_threat_intel.converter import ConnectorConverter
from microsoft_defender_threat_intel.errors import ConnectorWarning, ConnectorError


class Connector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: ConnectorSettings,
        converter: ConnectorConverter,
        client: ConnectorClient,
    ) -> None:
        self.helper = helper
        self.config = config
        self.converter = converter
        self.client = client

    @property
    def state(self) -> dict[str, Any]:
        return self.helper.get_state() or {}

    def update_state(self, **kwargs: Any) -> None:
        self.helper.set_state(state={**self.state, **kwargs})

    def initiate_work(self, friendly_name: str) -> str:
        return self.helper.api.work.initiate_work(
            connector_id=self.helper.connect_id, friendly_name=friendly_name
        )

    def finalize_work(self, work_id: str, message: str) -> None:
        self.helper.api.work.to_processed(work_id=work_id, message=message)

    def create_and_send_bundles(
        self, stix_objects: list[stix2.v21._STIXBase21], work_id: str | None = None
    ) -> None:
        if not stix_objects:
            self.helper.connector_logger.info("No STIX objects to process.")
            if work_id:
                # FIXME: logger.info/warning ?
                self.helper.api.work.delete_work(work_id=work_id)
            return

        if not work_id:
            work_id = self.initiate_work(friendly_name=self.helper.connect_name)

        bundle = self.helper.stix2_create_bundle(
            items=stix_objects + [self.converter.author, self.converter.tlp_marking]
        )
        bundles_sent = self.helper.send_stix2_bundle(
            bundle=bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )
        self.helper.connector_logger.info(
            f"Sent {len(bundles_sent)} STIX objects to OpenCTI."
        )
        self.finalize_work(work_id, "Connector successfully run")

    def process_data(self) -> None:
        # stix_objects = []
        # self.create_and_send_bundles(stix_objects=stix_objects)
        a = self.client.fetch_articles()
        raise NotImplementedError("abc")

    def process(self) -> None:
        meta = {"connector_name": self.helper.connect_name}
        try:
            self.helper.connector_logger.info("Running connector...", meta=meta)
            self.process_data()
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped by user.", meta=meta)
            sys.exit(0)
        except ConnectorWarning as e:
            meta["warning"] = e
            self.helper.connector_logger.warning(e, meta=meta)
        except ConnectorError as e:
            meta["error"] = e
            self.helper.connector_logger.error(e, meta=meta)
        except Exception as e:
            traceback.print_exc()
            meta["error"] = e
            self.helper.connector_logger.error(f"Unexpected error: {e}", meta=meta)

    def run(self, duration_period: datetime.timedelta) -> None:
        self.helper.connector_logger.info("Starting connector...")
        self.helper.schedule_process(
            message_callback=self.process,
            duration_period=duration_period.total_seconds(),
        )
