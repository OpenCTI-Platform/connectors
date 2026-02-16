"""OpenCTI valhalla connector core module."""

import sys
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from pycti import OpenCTIConnectorHelper
from stix2 import TLP_AMBER, TLP_WHITE
from valhalla.settings import ConnectorSettings
from valhallaAPI.valhalla import ValhallaAPI

from .knowledge import KnowledgeImporter
from .models import Status


class Valhalla:
    """OpenCTI valhalla main class"""

    _STATE_LAST_RUN = "last_run"
    _VALHALLA_LAST_VERSION = "valhalla_last_version"

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        api_key = (
            self.config.valhalla.api_key.get_secret_value()
            if self.config.valhalla.api_key
            else ""
        )
        self.helper.connector_logger.info(f"loaded valhalla config: {self.config}")
        if api_key == "":
            default_marking = TLP_WHITE
        else:
            default_marking = TLP_AMBER

        self.valhalla_client = ValhallaAPI(api_key=api_key)

        self.knowledge_importer = KnowledgeImporter(
            self.helper,
            default_marking,
            self.valhalla_client,
        )

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_data,
            duration_period=self.config.connector.duration_period,
        )

    def process_data(self) -> None:
        self.helper.log_info("starting valhalla connector...")
        self.helper.metric.state("idle")
        try:
            status_data = self.valhalla_client.get_status()
            api_status = Status.parse_obj(status_data)
            self.helper.log_info(f"current valhalla status: {api_status}")
            current_state = self._load_state()
            self.helper.log_info(f"loaded state: {current_state}")
            last_valhalla_version = self._get_state_value(
                current_state, self._VALHALLA_LAST_VERSION
            )
            if self._check_version(last_valhalla_version, api_status.version):
                self.helper.log_info("running valhalla importer")
                self.helper.metric.inc("run_count")
                self.helper.metric.state("running")
                now = datetime.now(timezone.utc)
                friendly_name = (
                    f"Valhalla run @ {now.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"for upstream database version {api_status.version}"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                knowledge_importer_state = self.knowledge_importer.run(work_id)
                self.helper.log_info("done with running valhalla importer")
                new_state = current_state.copy()
                new_state.update(knowledge_importer_state)
                new_state[self._STATE_LAST_RUN] = int(now.timestamp())
                new_state[self._VALHALLA_LAST_VERSION] = api_status.version
                self.helper.log_info(f"storing new state: {new_state}")
                self.helper.set_state(new_state)

                self.helper.api.work.to_processed(work_id, "Valhalla importer finished")
                self.helper.metric.state("idle")

        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("connector stop")
            self.helper.metric.state("stopped")
            sys.exit(0)

        except Exception as e:
            self.helper.log_error(str(e))
            self.helper.metric.state("stopped")
            sys.exit(0)

        if self.helper.connect_run_and_terminate:
            self.helper.log_info("Connector stop")
            self.helper.metric.state("stopped")
            self.helper.force_ping()
            sys.exit(0)

    def _load_state(self) -> Dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    @staticmethod
    def _get_state_value(
        state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    def _check_version(self, last_version: Optional[int], current_version: int) -> bool:
        if last_version is None:
            return True
        return current_version > last_version
