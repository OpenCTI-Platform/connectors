"""Kaspersky connector module."""

import sys
import time
from typing import Any, Dict, Mapping, Optional

from kaspersky.client import KasperskyClient
from kaspersky.master_ioc.importer import MasterIOCImporter
from kaspersky.master_yara.importer import MasterYaraImporter
from kaspersky.publication.importer import PublicationImporter
from kaspersky.settings import ConnectorSettings
from kaspersky.utils import (
    DEFAULT_TLP_MARKING_DEFINITION,
    create_organization,
    get_tlp_string_marking_definition,
    timestamp_to_datetime,
)
from pycti import OpenCTIConnectorHelper
from stix2 import Identity, MarkingDefinition


class KasperskyConnector:
    """Kaspersky connector."""

    _CONFIG_REPORT_STATUS_MAPPING = {
        "new": 0,
        "in progress": 1,
        "analyzed": 2,
        "closed": 3,
    }

    _DEFAULT_AUTHOR = "Kaspersky"

    _SCOPE_PUBLICATION = "publication"
    _SCOPE_MASTER_IOC = "master_ioc"
    _SCOPE_MASTER_YARA = "master_yara"

    _CONNECTOR_RUN_INTERVAL_SEC = 60

    _STATE_LATEST_RUN_TIMESTAMP = "latest_run_timestamp"

    def __init__(self):
        """Initialize Kaspersky connector."""
        self.config = ConnectorSettings()
        kaspersky_config = self.config.kaspersky

        # Kaspersky connector configuration.
        base_url = kaspersky_config.base_url
        user = kaspersky_config.user
        password = kaspersky_config.password.get_secret_value()
        certificate_path = kaspersky_config.certificate_path

        tlp = kaspersky_config.tlp
        tlp_marking = self._convert_tlp_to_marking_definition(tlp)

        create_observables = kaspersky_config.create_observables
        create_indicators = kaspersky_config.create_indicators

        scopes = set(kaspersky_config.scopes)

        publication_start_timestamp = kaspersky_config.publication_start_timestamp
        publication_report_type = kaspersky_config.publication_report_type
        publication_report_status = (
            self._convert_report_status_str_to_report_status_int(
                kaspersky_config.publication_report_status
            )
        )
        publication_report_ignore_prefixes = set(
            kaspersky_config.publication_report_ignore_prefixes
        )
        publication_excluded_ioc_indicator_types = set(
            kaspersky_config.publication_excluded_ioc_indicator_types
        )

        master_ioc_fetch_weekday = kaspersky_config.master_ioc_fetch_weekday or None
        master_ioc_excluded_ioc_indicator_types = set(
            kaspersky_config.master_ioc_excluded_ioc_indicator_types
        )
        master_ioc_report_type = kaspersky_config.master_ioc_report_type
        master_ioc_report_status = self._convert_report_status_str_to_report_status_int(
            kaspersky_config.master_ioc_report_status
        )

        master_yara_fetch_weekday = kaspersky_config.master_yara_fetch_weekday or None
        master_yara_include_report = kaspersky_config.master_yara_include_report
        master_yara_report_type = kaspersky_config.master_yara_report_type
        master_yara_report_status = (
            self._convert_report_status_str_to_report_status_int(
                kaspersky_config.master_yara_report_status
            )
        )

        # Create OpenCTI connector helper.
        self.helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())

        # Create Kaspersky client.
        self.client = KasperskyClient(
            self.helper, base_url, user, password, certificate_path
        )

        # Create connector author identity.
        author = self._create_author()

        # Create importers.
        importers = []

        # Publication importer.
        if self._SCOPE_PUBLICATION in scopes:
            publication_importer = PublicationImporter(
                self.helper,
                self.client,
                author,
                tlp_marking,
                create_observables,
                create_indicators,
                publication_start_timestamp,
                publication_report_type,
                publication_report_status,
                publication_report_ignore_prefixes,
                publication_excluded_ioc_indicator_types,
            )

            importers.append(publication_importer)

        # Master IOC importer.
        if self._SCOPE_MASTER_IOC in scopes:
            master_ioc_importer = MasterIOCImporter(
                self.helper,
                self.client,
                author,
                tlp_marking,
                create_observables,
                create_indicators,
                master_ioc_fetch_weekday,
                master_ioc_excluded_ioc_indicator_types,
                master_ioc_report_type,
                master_ioc_report_status,
            )

            importers.append(master_ioc_importer)

        # Master YARA importer.
        if self._SCOPE_MASTER_YARA in scopes:
            master_yara_importer = MasterYaraImporter(
                self.helper,
                self.client,
                author,
                tlp_marking,
                master_yara_fetch_weekday,
                master_yara_include_report,
                master_yara_report_type,
                master_yara_report_status,
            )

            importers.append(master_yara_importer)

        self.importers = importers

    def close(self) -> None:
        """Close Kaspersky connector."""
        self.client.close()

    @classmethod
    def _convert_tlp_to_marking_definition(
        cls, tlp_value: Optional[str]
    ) -> MarkingDefinition:
        if tlp_value is None:
            return DEFAULT_TLP_MARKING_DEFINITION

        return get_tlp_string_marking_definition(tlp_value)

    @staticmethod
    def _create_author() -> Identity:
        name = KasperskyConnector._DEFAULT_AUTHOR
        return create_organization(name)

    @classmethod
    def _convert_report_status_str_to_report_status_int(cls, report_status: str) -> int:
        return cls._CONFIG_REPORT_STATUS_MAPPING[report_status.lower()]

    def run(self) -> None:
        """Run Kaspersky connector."""
        self._info("Starting Kaspersky connector...")

        if not self.importers:
            self._error("No import scope(s) configured")
            return

        while True:
            self._info("Running Kaspersky connector...")
            run_interval = self._CONNECTOR_RUN_INTERVAL_SEC

            try:
                timestamp = self._current_unix_timestamp()

                current_state = self._load_state()
                self._info("Loaded state: {0}", current_state)

                last_run = self._get_state_value(
                    current_state, self._STATE_LATEST_RUN_TIMESTAMP
                )
                if self._is_scheduled(last_run, timestamp):
                    self.helper.metric.inc("run_count")
                    self.helper.metric.state("running")
                    work_id = self._initiate_work(timestamp)

                    new_state = current_state.copy()

                    for importer in self.importers:
                        importer_state = importer.start(work_id, current_state)
                        if importer_state:
                            self._info(
                                "Updating global state with importer state: {0}",
                                importer_state,
                            )
                            new_state.update(importer_state)

                    new_state[self._STATE_LATEST_RUN_TIMESTAMP] = (
                        self._current_unix_timestamp()
                    )

                    self._info("Storing new state: {0}", new_state)

                    self.helper.set_state(new_state)

                    message = (
                        f"State stored, next run in: {self._get_interval()} seconds"
                    )

                    self._info(message)

                    self._complete_work(work_id, message)
                else:
                    next_run = self._get_interval() - (timestamp - last_run)
                    run_interval = min(run_interval, next_run)

                    self._info(
                        "Connector will not run, next run in: {0} seconds", next_run
                    )

                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    self.helper.metric.state("stopped")
                    self.helper.force_ping()
                    sys.exit(0)

                self.helper.metric.state("idle")
                self._sleep(delay_sec=run_interval)

            except (KeyboardInterrupt, SystemExit):
                self._info("Kaspersky connector stop")
                self.helper.metric.state("stopped")
                sys.exit(0)

            except Exception as e:  # noqa: B902
                self._error("Kaspersky connector internal error: {0}", str(e))
                self.helper.metric.inc("error_count")

                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    self.helper.metric.state("stopped")
                    sys.exit(0)

                self.helper.metric.state("idle")
                self._sleep()

    def _initiate_work(self, timestamp: int) -> str:
        datetime_str = timestamp_to_datetime(timestamp)
        friendly_name = f"{self.helper.connect_name} @ {datetime_str}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        self._info("New work '{0}' initiated", work_id)

        return work_id

    def _complete_work(self, work_id: str, message: str) -> None:
        self.helper.api.work.to_processed(work_id, message)

    @classmethod
    def _sleep(cls, delay_sec: Optional[int] = None) -> None:
        sleep_delay = (
            delay_sec if delay_sec is not None else cls._CONNECTOR_RUN_INTERVAL_SEC
        )
        time.sleep(sleep_delay)

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

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

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self._info("Kaspersky connector clean run")
            return True

        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    def _get_interval(self) -> int:
        return int(self.config.connector.duration_period.total_seconds())

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)
