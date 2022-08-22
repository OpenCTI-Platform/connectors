"""Kaspersky connector module."""

import os
import sys
import time
from typing import Any, Dict, List, Mapping, Optional

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable  # type: ignore
from stix2 import Identity, MarkingDefinition  # type: ignore

from kaspersky.client import KasperskyClient
from kaspersky.master_ioc.importer import MasterIOCImporter
from kaspersky.master_yara.importer import MasterYaraImporter
from kaspersky.publication.importer import PublicationImporter
from kaspersky.utils import (
    DEFAULT_TLP_MARKING_DEFINITION,
    convert_comma_separated_str_to_list,
    create_organization,
    get_tlp_string_marking_definition,
    timestamp_to_datetime,
)


class KasperskyConnector:
    """Kaspersky connector."""

    _CONFIG_NAMESPACE = "kaspersky"

    _CONFIG_BASE_URL = f"{_CONFIG_NAMESPACE}.base_url"
    _CONFIG_USER = f"{_CONFIG_NAMESPACE}.user"
    _CONFIG_PASSWORD = f"{_CONFIG_NAMESPACE}.password"
    _CONFIG_CERTIFICATE_PATH = f"{_CONFIG_NAMESPACE}.certificate_path"

    _CONFIG_TLP = f"{_CONFIG_NAMESPACE}.tlp"
    _CONFIG_CREATE_OBSERVABLES = f"{_CONFIG_NAMESPACE}.create_observables"
    _CONFIG_CREATE_INDICATORS = f"{_CONFIG_NAMESPACE}.create_indicators"

    _CONFIG_SCOPES = f"{_CONFIG_NAMESPACE}.scopes"

    _CONFIG_PUBLICATION_PREFIX = f"{_CONFIG_NAMESPACE}.publication_"
    _CONFIG_PUBLICATION_START_TIMESTAMP = f"{_CONFIG_PUBLICATION_PREFIX}start_timestamp"
    _CONFIG_PUBLICATION_REPORT_TYPE = f"{_CONFIG_PUBLICATION_PREFIX}report_type"
    _CONFIG_PUBLICATION_REPORT_STATUS = f"{_CONFIG_PUBLICATION_PREFIX}report_status"
    _CONFIG_PUBLICATION_REPORT_IGNORE_PREFIXES = (
        f"{_CONFIG_PUBLICATION_PREFIX}report_ignore_prefixes"
    )
    _CONFIG_PUBLICATION_EXCLUDED_IOC_INDICATOR_TYPES = (
        f"{_CONFIG_PUBLICATION_PREFIX}excluded_ioc_indicator_types"
    )

    _CONFIG_MASTER_IOC_PREFIX = f"{_CONFIG_NAMESPACE}.master_ioc_"
    _CONFIG_MASTER_IOC_FETCH_WEEKDAY = f"{_CONFIG_MASTER_IOC_PREFIX}fetch_weekday"
    _CONFIG_MASTER_IOC_EXCLUDED_IOC_INDICATOR_TYPES = (
        f"{_CONFIG_MASTER_IOC_PREFIX}excluded_ioc_indicator_types"
    )
    _CONFIG_MASTER_IOC_REPORT_TYPE = f"{_CONFIG_MASTER_IOC_PREFIX}report_type"
    _CONFIG_MASTER_IOC_REPORT_STATUS = f"{_CONFIG_MASTER_IOC_PREFIX}report_status"

    _CONFIG_MASTER_YARA_PREFIX = f"{_CONFIG_NAMESPACE}.master_yara_"
    _CONFIG_MASTER_YARA_FETCH_WEEKDAY = f"{_CONFIG_MASTER_YARA_PREFIX}fetch_weekday"
    _CONFIG_MASTER_YARA_INCLUDE_REPORT = f"{_CONFIG_MASTER_YARA_PREFIX}include_report"
    _CONFIG_MASTER_YARA_REPORT_TYPE = f"{_CONFIG_MASTER_YARA_PREFIX}report_type"
    _CONFIG_MASTER_YARA_REPORT_STATUS = f"{_CONFIG_MASTER_YARA_PREFIX}report_status"

    _CONFIG_INTERVAL_SEC = f"{_CONFIG_NAMESPACE}.interval_sec"

    _CONFIG_UPDATE_EXISTING_DATA = "connector.update_existing_data"

    _CONFIG_REPORT_STATUS_MAPPING = {
        "new": 0,
        "in progress": 1,
        "analyzed": 2,
        "closed": 3,
    }

    _DEFAULT_CREATE_OBSERVABLES = True
    _DEFAULT_CREATE_INDICATORS = True
    _DEFAULT_INCLUDE_REPORT = True
    _DEFAULT_REPORT_STATUS = "new"
    _DEFAULT_REPORT_TYPE = "threat-report"

    _DEFAULT_AUTHOR = "Kaspersky"

    _SCOPE_PUBLICATION = "publication"
    _SCOPE_MASTER_IOC = "master_ioc"
    _SCOPE_MASTER_YARA = "master_yara"

    _CONNECTOR_RUN_INTERVAL_SEC = 60

    _STATE_LATEST_RUN_TIMESTAMP = "latest_run_timestamp"

    def __init__(self):
        """Initialize Kaspersky connector."""
        config = self._read_configuration()

        # Kaspersky connector configuration.
        base_url = self._get_configuration(config, self._CONFIG_BASE_URL)
        user = self._get_configuration(config, self._CONFIG_USER)
        password = self._get_configuration(config, self._CONFIG_PASSWORD)
        certificate_path = self._get_configuration(
            config, self._CONFIG_CERTIFICATE_PATH
        )

        tlp = self._get_configuration(config, self._CONFIG_TLP)
        tlp_marking = self._convert_tlp_to_marking_definition(tlp)

        create_observables = self._get_configuration(
            config, self._CONFIG_CREATE_OBSERVABLES
        )
        if create_observables is None:
            create_observables = self._DEFAULT_CREATE_OBSERVABLES
        else:
            create_observables = bool(create_observables)

        create_indicators = self._get_configuration(
            config, self._CONFIG_CREATE_INDICATORS
        )
        if create_indicators is None:
            create_indicators = self._DEFAULT_CREATE_INDICATORS
        else:
            create_indicators = bool(create_indicators)

        scopes_str = self._get_configuration(config, self._CONFIG_SCOPES)
        scopes = set()
        if scopes_str is not None:
            scopes = set(convert_comma_separated_str_to_list(scopes_str))

        publication_start_timestamp = self._get_configuration(
            config, self._CONFIG_PUBLICATION_START_TIMESTAMP, is_number=True
        )

        publication_report_type = self._get_configuration(
            config, self._CONFIG_PUBLICATION_REPORT_TYPE
        )
        if not publication_report_type:
            publication_report_type = self._DEFAULT_REPORT_TYPE

        publication_report_status_str = self._get_configuration(
            config, self._CONFIG_PUBLICATION_REPORT_STATUS
        )
        if not publication_report_status_str:
            publication_report_status_str = self._DEFAULT_REPORT_STATUS

        publication_report_status = (
            self._convert_report_status_str_to_report_status_int(
                publication_report_status_str
            )
        )

        publication_report_ignore_prefixes_str = self._get_configuration(
            config, self._CONFIG_PUBLICATION_REPORT_IGNORE_PREFIXES
        )
        publication_report_ignore_prefixes = set()
        if publication_report_ignore_prefixes_str is not None:
            publication_report_ignore_prefixes = set(
                convert_comma_separated_str_to_list(
                    publication_report_ignore_prefixes_str
                )
            )

        publication_excluded_ioc_indicator_types_str = self._get_configuration(
            config, self._CONFIG_PUBLICATION_EXCLUDED_IOC_INDICATOR_TYPES
        )
        publication_excluded_ioc_indicator_types = set()
        if publication_excluded_ioc_indicator_types_str is not None:
            publication_excluded_ioc_indicator_types = set(
                convert_comma_separated_str_to_list(
                    publication_excluded_ioc_indicator_types_str
                )
            )

        master_ioc_fetch_weekday = self._get_configuration(
            config, self._CONFIG_MASTER_IOC_FETCH_WEEKDAY, is_number=True
        )
        if not master_ioc_fetch_weekday:
            master_ioc_fetch_weekday = None

        master_ioc_excluded_ioc_indicator_types_str = self._get_configuration(
            config, self._CONFIG_MASTER_IOC_EXCLUDED_IOC_INDICATOR_TYPES
        )
        master_ioc_excluded_ioc_indicator_types = set()
        if master_ioc_excluded_ioc_indicator_types_str is not None:
            master_ioc_excluded_ioc_indicator_types = set(
                convert_comma_separated_str_to_list(
                    master_ioc_excluded_ioc_indicator_types_str
                )
            )

        master_ioc_report_type = self._get_configuration(
            config, self._CONFIG_MASTER_IOC_REPORT_TYPE
        )
        if not master_ioc_report_type:
            master_ioc_report_type = self._DEFAULT_REPORT_TYPE

        master_ioc_report_status_str = self._get_configuration(
            config, self._CONFIG_MASTER_IOC_REPORT_STATUS
        )
        if not master_ioc_report_status_str:
            master_ioc_report_status_str = self._DEFAULT_REPORT_STATUS

        master_ioc_report_status = self._convert_report_status_str_to_report_status_int(
            master_ioc_report_status_str
        )

        master_yara_fetch_weekday = self._get_configuration(
            config, self._CONFIG_MASTER_YARA_FETCH_WEEKDAY, is_number=True
        )
        if not master_yara_fetch_weekday:
            master_yara_fetch_weekday = None

        master_yara_include_report = self._get_configuration(
            config, self._CONFIG_MASTER_YARA_INCLUDE_REPORT
        )
        if master_yara_include_report is None:
            master_yara_include_report = self._DEFAULT_INCLUDE_REPORT
        else:
            master_yara_include_report = bool(master_yara_include_report)

        master_yara_report_type = self._get_configuration(
            config, self._CONFIG_MASTER_YARA_REPORT_TYPE
        )
        if not master_yara_report_type:
            master_yara_report_type = self._DEFAULT_REPORT_TYPE

        master_yara_report_status_str = self._get_configuration(
            config, self._CONFIG_MASTER_YARA_REPORT_STATUS
        )
        if not master_yara_report_status_str:
            master_yara_report_status_str = self._DEFAULT_REPORT_STATUS

        master_yara_report_status = (
            self._convert_report_status_str_to_report_status_int(
                master_yara_report_status_str
            )
        )

        self.interval_sec = self._get_configuration(
            config, self._CONFIG_INTERVAL_SEC, is_number=True
        )

        update_existing_data = bool(
            self._get_configuration(config, self._CONFIG_UPDATE_EXISTING_DATA)
        )

        # Create OpenCTI connector helper.
        self.helper = OpenCTIConnectorHelper(config)

        # Create Kaspersky client.
        self.client = KasperskyClient(base_url, user, password, certificate_path)

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
                update_existing_data,
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
                update_existing_data,
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
                update_existing_data,
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

    @staticmethod
    def _read_configuration() -> Dict[str, str]:
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        if not os.path.isfile(config_file_path):
            return {}

        return yaml.load(open(config_file_path), Loader=yaml.FullLoader)

    @classmethod
    def _get_configuration(
        cls, config: Dict[str, Any], config_name: str, is_number: bool = False
    ) -> Any:
        yaml_path = cls._get_yaml_path(config_name)
        env_var_name = cls._get_environment_variable_name(yaml_path)
        config_value = get_config_variable(
            env_var_name, yaml_path, config, isNumber=is_number
        )
        return config_value

    @staticmethod
    def _get_yaml_path(config_name: str) -> List[str]:
        return config_name.split(".")

    @staticmethod
    def _get_environment_variable_name(yaml_path: List[str]) -> str:
        return "_".join(yaml_path).upper()

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

                    new_state[
                        self._STATE_LATEST_RUN_TIMESTAMP
                    ] = self._current_unix_timestamp()

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
                    sys.exit(0)

                self._sleep(delay_sec=run_interval)

            except (KeyboardInterrupt, SystemExit):
                self._info("Kaspersky connector stop")
                sys.exit(0)

            except Exception as e:  # noqa: B902
                self._error("Kaspersky connector internal error: {0}", str(e))

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
        return int(self.interval_sec)

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)
