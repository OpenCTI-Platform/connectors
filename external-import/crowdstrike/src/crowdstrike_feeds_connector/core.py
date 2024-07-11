# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike connector core module."""
import os
import sys
import time
from typing import Any, Dict, List, Mapping, Optional

import stix2
import yaml
from crowdstrike_feeds_services.client.base_api import BaseCrowdstrikeClient
from crowdstrike_feeds_services.utils import (
    convert_comma_separated_str_to_list,
    create_organization,
    get_tlp_string_marking_definition,
    is_timestamp_in_future,
    timestamp_to_datetime,
)
from crowdstrike_feeds_services.utils.config_variables import ConfigCrowdstrike
from crowdstrike_feeds_services.utils.constants import DEFAULT_TLP_MARKING_DEFINITION
from pycti import OpenCTIConnectorHelper  # type: ignore

from .actor.importer import ActorImporter
from .importer import BaseImporter
from .indicator.importer import IndicatorImporter, IndicatorImporterConfig
from .report.importer import ReportImporter
from .rule.snort_suricata_master_importer import SnortMasterImporter
from .rule.yara_master_importer import YaraMasterImporter


class CrowdStrike:
    """CrowdStrike connector."""

    _CONFIG_SCOPE_ACTOR = "actor"
    _CONFIG_SCOPE_REPORT = "report"
    _CONFIG_SCOPE_INDICATOR = "indicator"
    _CONFIG_SCOPE_YARA_MASTER = "yara_master"
    _CONFIG_SCOPE_SNORT_SURICATA_MASTER = "snort_suricata_master"

    _CONFIG_REPORT_STATUS_MAPPING = {
        "new": 0,
        "in progress": 1,
        "analyzed": 2,
        "closed": 3,
    }

    _DEFAULT_CREATE_OBSERVABLES = True
    _DEFAULT_CREATE_INDICATORS = True
    _DEFAULT_REPORT_TYPE = "threat-report"
    _DEFAULT_INDICATOR_LOW_SCORE = 40

    _CONNECTOR_RUN_INTERVAL_SEC = 60

    _STATE_LAST_RUN = "last_run"

    def __init__(self) -> None:
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ConfigCrowdstrike()

        self.interval_sec = self.config.interval_sec

        scopes_str = self.config.scopes
        scopes = set()
        if scopes_str is not None:
            scopes = set(convert_comma_separated_str_to_list(scopes_str))

        tlp = self.config.tlp
        tlp_marking = self._convert_tlp_to_marking_definition(tlp)

        create_observables = self.config.create_observables
        if create_observables is None:
            create_observables = self._DEFAULT_CREATE_OBSERVABLES
        else:
            create_observables = bool(create_observables)

        create_indicators = self.config.create_indicators
        if create_indicators is None:
            create_indicators = self._DEFAULT_CREATE_INDICATORS
        else:
            create_indicators = bool(create_indicators)

        actor_start_timestamp = self.config.actor_start_timestamp
        if is_timestamp_in_future(actor_start_timestamp):
            raise ValueError("Actor start timestamp is in the future")

        report_start_timestamp = self.config.report_start_timestamp
        if is_timestamp_in_future(report_start_timestamp):
            raise ValueError("Report start timestamp is in the future")

        report_status_str = self.config.report_status
        report_status = self._convert_report_status_str_to_report_status_int(
            report_status_str
        )

        report_type = self.config.report_type
        if not report_type:
            report_type = self._DEFAULT_REPORT_TYPE

        report_include_types_str = self.config.report_include_types
        report_include_types = []
        if report_include_types_str is not None:
            report_include_types = convert_comma_separated_str_to_list(
                report_include_types_str
            )

        report_guess_malware = bool(self.config.report_guess_malware)

        indicator_start_timestamp = self.config.indicator_start_timestamp
        if is_timestamp_in_future(indicator_start_timestamp):
            raise ValueError("Indicator start timestamp is in the future")

        indicator_exclude_types_str = self.config.indicator_exclude_types
        indicator_exclude_types = []
        if indicator_exclude_types_str is not None:
            indicator_exclude_types = convert_comma_separated_str_to_list(
                indicator_exclude_types_str
            )

        indicator_low_score = self.config.indicator_low_score
        if indicator_low_score is None:
            indicator_low_score = self._DEFAULT_INDICATOR_LOW_SCORE

        indicator_low_score_labels_str = self.config.indicator_low_score_labels
        indicator_low_score_labels = []
        if indicator_low_score_labels_str is not None:
            indicator_low_score_labels = convert_comma_separated_str_to_list(
                indicator_low_score_labels_str
            )

        indicator_unwanted_labels_str = self.config.indicator_unwanted_labels
        indicator_unwanted_labels = []
        if indicator_unwanted_labels_str is not None:
            indicator_unwanted_labels = convert_comma_separated_str_to_list(
                indicator_unwanted_labels_str
            )

        update_existing_data = bool(self.config.update_existing_data)

        author = self._create_author()

        # Create OpenCTI connector helper.
        self.helper = OpenCTIConnectorHelper(self.config.load)

        # Create CrowdStrike client and importers.
        self.connect_cs = BaseCrowdstrikeClient(self.helper)

        # Create importers.
        importers: List[BaseImporter] = []

        if self._CONFIG_SCOPE_ACTOR in scopes:
            actor_importer = ActorImporter(
                self.helper,
                update_existing_data,
                author,
                actor_start_timestamp,
                tlp_marking,
            )

            importers.append(actor_importer)

        if self._CONFIG_SCOPE_REPORT in scopes:
            report_importer = ReportImporter(
                self.helper,
                update_existing_data,
                author,
                report_start_timestamp,
                tlp_marking,
                report_include_types,
                report_status,
                report_type,
                report_guess_malware,
            )

            importers.append(report_importer)

        if self._CONFIG_SCOPE_INDICATOR in scopes:
            indicator_importer_config = IndicatorImporterConfig(
                helper=self.helper,
                update_existing_data=update_existing_data,
                author=author,
                default_latest_timestamp=indicator_start_timestamp,
                tlp_marking=tlp_marking,
                create_observables=create_observables,
                create_indicators=create_indicators,
                exclude_types=indicator_exclude_types,
                report_status=report_status,
                report_type=report_type,
                indicator_low_score=indicator_low_score,
                indicator_low_score_labels=set(indicator_low_score_labels),
                indicator_unwanted_labels=set(indicator_unwanted_labels),
            )

            indicator_importer = IndicatorImporter(indicator_importer_config)
            importers.append(indicator_importer)

        if self._CONFIG_SCOPE_YARA_MASTER in scopes:
            yara_master_importer = YaraMasterImporter(
                self.helper,
                author,
                tlp_marking,
                update_existing_data,
                report_status,
                report_type,
            )

            importers.append(yara_master_importer)

        if self._CONFIG_SCOPE_SNORT_SURICATA_MASTER in scopes:
            snort_master_importer = SnortMasterImporter(
                self.helper,
                author,
                tlp_marking,
                update_existing_data,
                report_status,
                report_type,
            )

            importers.append(snort_master_importer)

        self.importers = importers

    @staticmethod
    def _read_configuration() -> Dict[str, str]:
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        if not os.path.isfile(config_file_path):
            return {}
        return yaml.load(open(config_file_path), Loader=yaml.FullLoader)

    @staticmethod
    def _create_author() -> stix2.Identity:
        return create_organization("CrowdStrike")

    @staticmethod
    def _get_yaml_path(config_name: str) -> List[str]:
        return config_name.split(".")

    @staticmethod
    def _get_environment_variable_name(yaml_path: List[str]) -> str:
        return "_".join(yaml_path).upper()

    @classmethod
    def _convert_tlp_to_marking_definition(
        cls, tlp_value: Optional[str]
    ) -> stix2.MarkingDefinition:
        if tlp_value is None:
            return DEFAULT_TLP_MARKING_DEFINITION
        return get_tlp_string_marking_definition(tlp_value)

    @classmethod
    def _convert_report_status_str_to_report_status_int(cls, report_status: str) -> int:
        return cls._CONFIG_REPORT_STATUS_MAPPING[report_status.lower()]

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

    @classmethod
    def _sleep(cls, delay_sec: Optional[int] = None) -> None:
        sleep_delay = (
            delay_sec if delay_sec is not None else cls._CONNECTOR_RUN_INTERVAL_SEC
        )
        time.sleep(sleep_delay)

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self._info("CrowdStrike connector clean run")
            return True

        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    def run(self):
        """Run CrowdStrike connector."""
        self._info("Starting CrowdStrike connector...")

        if not self.importers:
            self._error("Scope(s) not configured.")
            return

        while True:
            self._info("Running CrowdStrike connector...")
            run_interval = self._CONNECTOR_RUN_INTERVAL_SEC

            try:
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()

                self.helper.log_info(f"Loaded state: {current_state}")

                last_run = self._get_state_value(current_state, self._STATE_LAST_RUN)
                if self._is_scheduled(last_run, timestamp):
                    work_id = self._initiate_work(timestamp)

                    new_state = current_state.copy()

                    for importer in self.importers:
                        importer_state = importer.start(work_id, new_state)
                        new_state.update(importer_state)

                        self._info("Storing updated new state: {0}", new_state)
                        self.helper.set_state(new_state)

                    new_state[self._STATE_LAST_RUN] = self._current_unix_timestamp()

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
                    self.helper.force_ping()
                    sys.exit(0)

                self._sleep(delay_sec=run_interval)

            except (KeyboardInterrupt, SystemExit):
                self._info("CrowdStrike connector stopping...")
                sys.exit(0)

            except Exception as e:  # noqa: B902
                self._error("CrowdStrike connector internal error: {0}", str(e))

                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    sys.exit(0)

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

    def _get_interval(self) -> int:
        return int(self.interval_sec)

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)
