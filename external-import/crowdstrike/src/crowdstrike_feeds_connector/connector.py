"""OpenCTI CrowdStrike connector core module."""

import os
import sys
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast

import stix2
import yaml
from crowdstrike_feeds_services.client.base_api import BaseCrowdstrikeClient
from crowdstrike_feeds_services.utils import (
    create_organization,
    get_tlp_string_marking_definition,
    timestamp_to_datetime,
)
from crowdstrike_feeds_services.utils.attack_lookup import (
    AttackTechniqueLookup,
    AttackTechniqueLookupError,
)
from crowdstrike_feeds_services.utils.constants import DEFAULT_TLP_MARKING_DEFINITION

from .actor.importer import ActorImporter
from .importer import BaseImporter
from .indicator.importer import IndicatorImporter, IndicatorImporterConfig
from .malware.importer import MalwareImporter
from .report.importer import ReportImporter
from .rule.snort_suricata_master_importer import SnortMasterImporter
from .rule.yara_master_importer import YaraMasterImporter
from .vulnerability.importer import VulnerabilityImporter

if TYPE_CHECKING:
    from crowdstrike_feeds_connector.settings import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class CrowdStrike:
    """CrowdStrike connector."""

    _CONFIG_SCOPE_ACTOR = "actor"
    _CONFIG_SCOPE_REPORT = "report"
    _CONFIG_SCOPE_INDICATOR = "indicator"
    _CONFIG_SCOPE_VULNERABILITY = "vulnerability"
    _CONFIG_SCOPE_MALWARE = "malware"
    _CONFIG_SCOPE_YARA_MASTER = "yara_master"
    _CONFIG_SCOPE_SNORT_SURICATA_MASTER = "snort_suricata_master"

    _CONFIG_REPORT_STATUS_MAPPING = {
        "new": 0,
        "in progress": 1,
        "analyzed": 2,
        "closed": 3,
    }

    _STATE_LAST_RUN = "last_run"

    def __init__(
        self, config: "ConnectorSettings", helper: "OpenCTIConnectorHelper"
    ) -> None:
        """
        Initialize the connector with necessary configurations
        """

        self.config = config
        self.helper = helper

        scopes = self.config.crowdstrike.scopes
        tlp_marking = self._convert_tlp_to_marking_definition(
            self.config.crowdstrike.tlp
        )

        create_observables = self.config.crowdstrike.create_observables
        create_indicators = self.config.crowdstrike.create_indicators

        actor_start_timestamp = self.config.crowdstrike.actor_start_timestamp
        malware_start_timestamp = self.config.crowdstrike.malware_start_timestamp

        report_start_timestamp = self.config.crowdstrike.report_start_timestamp
        report_status = self._convert_report_status_str_to_report_status_int(
            self.config.crowdstrike.report_status
        )
        report_type = self.config.crowdstrike.report_type
        report_include_types = self.config.crowdstrike.report_include_types
        report_target_industries = self.config.crowdstrike.report_target_industries
        report_guess_malware = self.config.crowdstrike.report_guess_malware
        report_guess_relations = self.config.crowdstrike.report_guess_relations

        vulnerability_start_timestamp = (
            self.config.crowdstrike.vulnerability_start_timestamp
        )

        indicator_start_timestamp = self.config.crowdstrike.indicator_start_timestamp
        indicator_exclude_types = self.config.crowdstrike.indicator_exclude_types

        default_x_opencti_score = self.config.crowdstrike.default_x_opencti_score
        indicator_low_score = self.config.crowdstrike.indicator_low_score
        indicator_low_score_labels = self.config.crowdstrike.indicator_low_score_labels
        indicator_medium_score = self.config.crowdstrike.indicator_medium_score
        indicator_medium_score_labels = (
            self.config.crowdstrike.indicator_medium_score_labels
        )
        indicator_high_score = self.config.crowdstrike.indicator_high_score
        indicator_high_score_labels = (
            self.config.crowdstrike.indicator_high_score_labels
        )
        indicator_unwanted_labels = self.config.crowdstrike.indicator_unwanted_labels

        no_file_trigger_import = self.config.crowdstrike.no_file_trigger_import

        author = self._create_author()

        # Load MITRE ATT&CK Enterprise dataset once at startup (used for ATT&CK technique ID resolution)
        self.attack_lookup = None
        try:
            attack_version = self.config.crowdstrike.attack_version
            attack_url_override = (
                str(self.config.crowdstrike.attack_enterprise_url)
                if self.config.crowdstrike.attack_enterprise_url
                else None
            )
            self.attack_lookup = AttackTechniqueLookup(
                attack_version=attack_version,
                enterprise_attack_url=attack_url_override,
            )

            self.helper.log_info(
                f"Loaded ATT&CK Enterprise dataset ({attack_version}) from {self.attack_lookup.enterprise_attack_url} "
                f"with {len(self.attack_lookup.attack_techniques)} techniques"
            )
        except AttackTechniqueLookupError as e:
            # Degraded mode: label parser will skip ATT&CK technique resolution if lookup is unavailable.
            self.helper.log_warning(
                "Unable to load ATT&CK Enterprise dataset for technique resolution; "
                f"Attack Pattern creation from labels may be skipped. Error: {str(e)}"
            )

        # Create CrowdStrike client and importers.
        self.connect_cs = BaseCrowdstrikeClient(self.config, self.helper)

        # Create importers.
        importers: list[BaseImporter] = []

        if self._CONFIG_SCOPE_ACTOR in scopes:
            actor_importer = ActorImporter(
                self.config,
                self.helper,
                author,
                actor_start_timestamp,
                tlp_marking,
            )

            importers.append(actor_importer)

        if self._CONFIG_SCOPE_REPORT in scopes:
            indicator_config = {
                "default_latest_timestamp": indicator_start_timestamp,
                "create_observables": create_observables,
                "create_indicators": create_indicators,
                "exclude_types": indicator_exclude_types,
                "default_x_opencti_score": default_x_opencti_score,
                "indicator_low_score": indicator_low_score,
                "indicator_low_score_labels": set(indicator_low_score_labels),
                "indicator_medium_score": indicator_medium_score,
                "indicator_medium_score_labels": set(indicator_medium_score_labels),
                "indicator_high_score": indicator_high_score,
                "indicator_high_score_labels": set(indicator_high_score_labels),
                "indicator_unwanted_labels": set(indicator_unwanted_labels),
            }
            report_importer = ReportImporter(
                self.config,
                self.helper,
                author,
                report_start_timestamp,
                tlp_marking,
                report_include_types,
                report_target_industries,
                report_status,
                report_type,
                report_guess_malware,
                report_guess_relations,
                indicator_config,
                no_file_trigger_import,
                scopes=set(scopes),
            )

            importers.append(report_importer)

        if self._CONFIG_SCOPE_INDICATOR in scopes:
            indicator_importer_config = IndicatorImporterConfig(
                config=self.config,
                helper=self.helper,
                author=author,
                default_latest_timestamp=indicator_start_timestamp,
                tlp_marking=tlp_marking,
                create_observables=create_observables,
                create_indicators=create_indicators,
                exclude_types=indicator_exclude_types,
                report_status=report_status,
                report_type=report_type,
                default_x_opencti_score=default_x_opencti_score,
                indicator_low_score=indicator_low_score,
                indicator_low_score_labels=set(indicator_low_score_labels),
                indicator_medium_score=indicator_medium_score,
                indicator_medium_score_labels=set(indicator_medium_score_labels),
                indicator_high_score=indicator_high_score,
                indicator_high_score_labels=set(indicator_high_score_labels),
                indicator_unwanted_labels=set(indicator_unwanted_labels),
                no_file_trigger_import=no_file_trigger_import,
                scopes=set(scopes),
                attack_lookup=self.attack_lookup,
            )

            indicator_importer = IndicatorImporter(indicator_importer_config)
            importers.append(indicator_importer)

        if self._CONFIG_SCOPE_YARA_MASTER in scopes:
            yara_master_importer = YaraMasterImporter(
                self.config,
                self.helper,
                author,
                tlp_marking,
                report_status,
                report_type,
                no_file_trigger_import,
                scopes=scopes,
            )

            importers.append(yara_master_importer)

        if self._CONFIG_SCOPE_SNORT_SURICATA_MASTER in scopes:
            snort_master_importer = SnortMasterImporter(
                self.config,
                self.helper,
                author,
                tlp_marking,
                report_status,
                report_type,
                no_file_trigger_import,
                scopes=scopes,
            )

            importers.append(snort_master_importer)

        if self._CONFIG_SCOPE_VULNERABILITY in scopes:
            vulnerability_importer = VulnerabilityImporter(
                self.config,
                self.helper,
                author,
                vulnerability_start_timestamp,
                tlp_marking,
            )

            importers.append(vulnerability_importer)

        if self._CONFIG_SCOPE_MALWARE in scopes:
            malware_importer = MalwareImporter(
                self.config,
                self.helper,
                author,
                malware_start_timestamp,
                tlp_marking,
            )

            importers.append(malware_importer)

        self.importers = importers

    @staticmethod
    def _read_configuration() -> dict[str, str]:
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        if not os.path.isfile(config_file_path):
            return {}
        return yaml.load(open(config_file_path), Loader=yaml.FullLoader)

    @staticmethod
    def _create_author() -> stix2.Identity:
        return create_organization("CrowdStrike")

    @staticmethod
    def _get_yaml_path(config_name: str) -> list[str]:
        return config_name.split(".")

    @staticmethod
    def _get_environment_variable_name(yaml_path: list[str]) -> str:
        return "_".join(yaml_path).upper()

    @classmethod
    def _convert_tlp_to_marking_definition(
        cls, tlp_value: str | None
    ) -> stix2.MarkingDefinition:
        if tlp_value is None:
            return DEFAULT_TLP_MARKING_DEFINITION
        return get_tlp_string_marking_definition(tlp_value)

    @classmethod
    def _convert_report_status_str_to_report_status_int(cls, report_status: str) -> int:
        return cls._CONFIG_REPORT_STATUS_MAPPING[report_status.lower()]

    def _load_state(self) -> dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    @staticmethod
    def _get_state_value(
        state: Mapping[str, Any] | None, key: str, default: Any | None = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    def process_message(self):
        """Run CrowdStrike connector."""
        self._info("Starting CrowdStrike connector...")

        if not self.importers:
            self._error("Scope(s) not configured.")
            return

        self._info("Running CrowdStrike connector...")

        try:
            timestamp = self._current_unix_timestamp()
            current_state = self._load_state()

            self.helper.log_info(f"Loaded state: {current_state}")

            new_state = current_state.copy()

            for importer in self.importers:
                importer_name = importer.name or importer.__class__.__name__
                work_id = self._initiate_work(timestamp, importer_name)
                importer_state = importer.start(work_id, new_state)
                new_state.update(importer_state)

                self._info("Storing updated new state: {0}", new_state)
                self.helper.set_state(new_state)

                connect_name = self.helper.connect_name or "CrowdStrike"
                message = (
                    f"{connect_name} {importer_name} successfully run, storing last_run as "
                    + str(timestamp)
                )
                self.helper.api.work.to_processed(work_id, message)

            new_state[self._STATE_LAST_RUN] = self._current_unix_timestamp()

            self._info("Storing new state: {0}", new_state)
            self.helper.set_state(new_state)

        except (KeyboardInterrupt, SystemExit):
            self._info("CrowdStrike connector stopping...")
            sys.exit(0)

        except Exception as e:  # noqa: B902
            self._error("CrowdStrike connector internal error: {0}", str(e))

    def run(self):
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,  # type: ignore[arg-type]
        )

    def _initiate_work(self, timestamp: int, importer_name: str) -> str:
        datetime_str = timestamp_to_datetime(timestamp)
        friendly_name = (
            f"{self.helper.connect_name}/{importer_name} run @ {datetime_str}"
        )
        connect_id = self.helper.connect_id
        if not connect_id:
            raise ValueError("OpenCTI helper connect_id is not set")

        work_id = self.helper.api.work.initiate_work(
            cast(str, connect_id), friendly_name
        )
        work_id = cast(str, work_id)

        self._info(f"New '{importer_name}' work '{work_id}' initiated")
        return work_id

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)
