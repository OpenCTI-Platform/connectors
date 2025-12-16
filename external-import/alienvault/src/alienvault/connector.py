"""OpenCTI AlienVault connector module."""

import datetime
import os
import sys
import time
from typing import Any, Dict, List, Mapping, Optional

import stix2
import yaml
from alienvault.client import AlienVaultClient
from alienvault.importer import PulseImporter, PulseImporterConfig
from alienvault.settings import ConnectorSettings
from alienvault.utils import (
    convert_comma_separated_str_to_list,
    create_organization,
    get_tlp_string_marking_definition,
)
from alienvault.utils.constants import DEFAULT_TLP_MARKING_DEFINITION
from pycti.connector.opencti_connector_helper import (
    OpenCTIConnectorHelper,
    get_config_variable,
)


class AlienVault:
    """AlienVault connector."""

    _CONFIG_CONNECTOR_NAMESPACE = "connector"
    _CONFIG_NAMESPACE = "alienvault"
    _CONFIG_DURATION_PERIOD = f"{_CONFIG_CONNECTOR_NAMESPACE}.duration_period"
    _CONFIG_INTERVAL_SEC = f"{_CONFIG_NAMESPACE}.interval_sec"
    _CONFIG_BASE_URL = f"{_CONFIG_NAMESPACE}.base_url"
    _CONFIG_API_KEY = f"{_CONFIG_NAMESPACE}.api_key"
    _CONFIG_TLP = f"{_CONFIG_NAMESPACE}.tlp"
    _CONFIG_CREATE_OBSERVABLES = f"{_CONFIG_NAMESPACE}.create_observables"
    _CONFIG_CREATE_INDICATORS = f"{_CONFIG_NAMESPACE}.create_indicators"
    _CONFIG_PULSE_START_TIMESTAMP = f"{_CONFIG_NAMESPACE}.pulse_start_timestamp"
    _CONFIG_REPORT_STATUS = f"{_CONFIG_NAMESPACE}.report_status"
    _CONFIG_REPORT_TYPE = f"{_CONFIG_NAMESPACE}.report_type"
    _CONFIG_GUESS_MALWARE = f"{_CONFIG_NAMESPACE}.guess_malware"
    _CONFIG_GUESS_CVE = f"{_CONFIG_NAMESPACE}.guess_cve"
    _CONFIG_EXCLUDED_PULSE_INDICATOR_TYPES = (
        f"{_CONFIG_NAMESPACE}.excluded_pulse_indicator_types"
    )
    _CONFIG_ENABLE_RELATIONSHIPS = f"{_CONFIG_NAMESPACE}.enable_relationships"
    _CONFIG_ENABLE_ATTACK_PATTERNS_INDICATES = (
        f"{_CONFIG_NAMESPACE}.enable_attack_patterns_indicates"
    )
    _CONFIG_FILTER_INDICATORS = f"{_CONFIG_NAMESPACE}.filter_indicators"
    _CONFIG_REPORT_STATUS_MAPPING = {
        "new": 0,
        "in progress": 1,
        "analyzed": 2,
        "closed": 3,
    }
    _CONFIG_DEFAULT_X_OPENCTI_SCORE = f"{_CONFIG_NAMESPACE}.default_x_opencti_score"
    _CONFIG_X_OPENCTI_SCORE_IP = f"{_CONFIG_NAMESPACE}.x_opencti_score_ip"
    _CONFIG_X_OPENCTI_SCORE_DOMAIN = f"{_CONFIG_NAMESPACE}.x_opencti_score_domain"
    _CONFIG_X_OPENCTI_SCORE_HOSTNAME = f"{_CONFIG_NAMESPACE}.x_opencti_score_hostname"
    _CONFIG_X_OPENCTI_SCORE_EMAIL = f"{_CONFIG_NAMESPACE}.x_opencti_score_email"
    _CONFIG_X_OPENCTI_SCORE_FILE = f"{_CONFIG_NAMESPACE}.x_opencti_score_file"
    _CONFIG_X_OPENCTI_SCORE_URL = f"{_CONFIG_NAMESPACE}.x_opencti_score_url"
    _CONFIG_X_OPENCTI_SCORE_MUTEX = f"{_CONFIG_NAMESPACE}.x_opencti_score_mutex"
    _CONFIG_X_OPENCTI_SCORE_CRYPTOCURRENCY_WALLET = (
        f"{_CONFIG_NAMESPACE}.x_opencti_score_cryptocurrency_wallet"
    )
    _DEFAULT_CREATE_OBSERVABLES = True
    _DEFAULT_CREATE_INDICATORS = True
    _DEFAULT_FILTER_INDICATORS = False
    _DEFAULT_REPORT_TYPE = "threat-report"
    _DEFAULT_ENABLE_RELATIONSHIPS = True
    _DEFAULT_ENABLE_ATTACK_PATTERNS_INDICATES = True
    _DEFAULT_INTERVAL_SEC = 1800
    _DEFAULT_DEFAULT_X_OPENCTI_SCORE = 50
    _STATE_LAST_RUN = "last_run"

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """Initialize AlienVault connector."""
        self.config = config
        self.helper = helper
        base_url = self.config.alienvault.base_url
        api_key = self.config.alienvault.api_key.get_secret_value()
        tlp = self.config.alienvault.tlp
        tlp_marking = self._convert_tlp_to_marking_definition(tlp)
        create_observables = self.config.alienvault.create_observables
        create_indicators = self.config.alienvault.create_indicators
        filter_indicators = self.config.alienvault.filter_indicators
        default_latest_pulse_timestamp = self.config.alienvault.pulse_start_timestamp
        report_status_str = self.config.alienvault.report_status
        report_status = self._convert_report_status_str_to_report_status_int(
            report_status_str
        )
        report_type = self.config.alienvault.report_type
        if not report_type:
            report_type = self._DEFAULT_REPORT_TYPE
        guess_malware = self.config.alienvault.guess_malware
        guess_cve = self.config.alienvault.guess_cve
        excluded_pulse_indicator_types_str = (
            self.config.alienvault.excluded_pulse_indicator_types
        )
        excluded_pulse_indicator_types = set()
        if excluded_pulse_indicator_types_str is not None:
            excluded_pulse_indicator_types_list = convert_comma_separated_str_to_list(
                excluded_pulse_indicator_types_str
            )
            excluded_pulse_indicator_types = set(excluded_pulse_indicator_types_list)
        enable_relationships = self.config.alienvault.enable_relationships
        enable_attack_patterns_indicates = (
            self.config.alienvault.enable_attack_patterns_indicates
        )
        default_x_opencti_score = self.config.alienvault.default_x_opencti_score
        x_opencti_score_ip = self.config.alienvault.x_opencti_score_ip
        x_opencti_score_domain = self.config.alienvault.x_opencti_score_domain
        x_opencti_score_hostname = self.config.alienvault.x_opencti_score_hostname
        x_opencti_score_email = self.config.alienvault.x_opencti_score_email
        x_opencti_score_file = self.config.alienvault.x_opencti_score_file
        x_opencti_score_url = self.config.alienvault.x_opencti_score_url
        x_opencti_score_mutex = self.config.alienvault.x_opencti_score_mutex
        x_opencti_score_cryptocurrency_wallet = (
            self.config.alienvault.x_opencti_score_cryptocurrency_wallet
        )
        self.duration_period = self.config.connector.duration_period
        self.interval_sec = self.config.alienvault.interval_sec
        if not self.interval_sec:
            self.interval_sec = self._DEFAULT_INTERVAL_SEC
        author = self._create_author()
        client = AlienVaultClient(base_url, api_key)
        pulse_importer_config = PulseImporterConfig(
            helper=self.helper,
            client=client,
            author=author,
            tlp_marking=tlp_marking,
            create_observables=create_observables,
            create_indicators=create_indicators,
            default_latest_timestamp=default_latest_pulse_timestamp,
            report_status=report_status,
            report_type=report_type,
            guess_malware=guess_malware,
            guess_cve=guess_cve,
            excluded_pulse_indicator_types=excluded_pulse_indicator_types,
            filter_indicators=filter_indicators,
            enable_relationships=enable_relationships,
            enable_attack_patterns_indicates=enable_attack_patterns_indicates,
            default_x_opencti_score=default_x_opencti_score,
            x_opencti_score_ip=x_opencti_score_ip,
            x_opencti_score_domain=x_opencti_score_domain,
            x_opencti_score_hostname=x_opencti_score_hostname,
            x_opencti_score_email=x_opencti_score_email,
            x_opencti_score_file=x_opencti_score_file,
            x_opencti_score_url=x_opencti_score_url,
            x_opencti_score_mutex=x_opencti_score_mutex,
            x_opencti_score_cryptocurrency_wallet=x_opencti_score_cryptocurrency_wallet,
        )
        self.pulse_importer = PulseImporter(pulse_importer_config)

    @staticmethod
    def _create_author() -> stix2.Identity:
        return create_organization("AlienVault")

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
    ) -> stix2.MarkingDefinition:
        if tlp_value is None:
            return DEFAULT_TLP_MARKING_DEFINITION
        return get_tlp_string_marking_definition(tlp_value)

    @classmethod
    def _convert_report_status_str_to_report_status_int(cls, report_status: str) -> int:
        return cls._CONFIG_REPORT_STATUS_MAPPING[report_status.lower()]

    def run(self):
        if self.duration_period:
            self.helper.schedule_iso(
                message_callback=self.process_message,
                duration_period=self.duration_period,
            )
        else:
            self.helper.schedule_unit(
                message_callback=self.process_message,
                duration_period=self.interval_sec,
                time_unit=self.helper.TimeUnit.SECONDS,
            )

    def process_message(self):
        """Run AlienVault connector."""
        self._info("Starting AlienVault connector...")
        try:
            timestamp = self._current_unix_timestamp()
            current_state = self._load_state()
            self._info("Loaded state: {0}", current_state)
            now = datetime.datetime.utcfromtimestamp(timestamp)
            friendly_name = "AlienVault run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            pulse_import_state = self.pulse_importer.run(current_state, work_id)
            new_state = current_state.copy()
            new_state.update(pulse_import_state)
            new_state[self._STATE_LAST_RUN] = self._current_unix_timestamp()
            self._info("Storing new state: {0}", new_state)
            self.helper.set_state(new_state)
            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(timestamp)
            )
            self.helper.api.work.to_processed(work_id, message)
            self._info(message)
        except (KeyboardInterrupt, SystemExit):
            self._info("Connector stopping...")
            sys.exit(0)
        except Exception as e:
            self._error("AlienVault connector internal error: {0}", str(e))

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

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)
