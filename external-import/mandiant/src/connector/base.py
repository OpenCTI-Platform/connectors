import importlib
import json
import os
import sys
import time
from datetime import timedelta
from typing import Any

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .api import OFFSET_PAGINATION, MandiantAPI
from .constants import (
    BATCH_REPORT_SIZE,
    DEFAULT_TLP_MARKING_DEFINITION,
    STATE_END,
    STATE_LAST_RUN,
    STATE_OFFSET,
    STATE_START,
    STATEMENT_MARKINGS,
    TLP_MARKING_DEFINITION_MAPPING,
)
from .errors import StateError
from .utils import Timestamp


class Mandiant:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            config,
            default="PT5M",
        )

        self.mandiant_api_v4_key_id = get_config_variable(
            "MANDIANT_API_V4_KEY_ID", ["mandiant", "api_v4_key_id"], config
        )
        self.mandiant_api_v4_key_secret = get_config_variable(
            "MANDIANT_API_V4_KEY_SECRET", ["mandiant", "api_v4_key_secret"], config
        )
        self.mandiant_import_start_date = get_config_variable(
            "MANDIANT_IMPORT_START_DATE",
            ["mandiant", "import_start_date"],
            config,
            default="2023-01-01",
        )
        self.mandiant_indicator_import_start_date = get_config_variable(
            "MANDIANT_INDICATOR_IMPORT_START_DATE",
            ["mandiant", "indicator_import_start_date"],
            config,
            default="2023-01-01",
        )
        self.mandiant_import_period = get_config_variable(
            "MANDIANT_IMPORT_PERIOD",
            ["mandiant", "import_period"],
            config,
            isNumber=True,
            default=1,
        )
        self.mandiant_create_notes = get_config_variable(
            "MANDIANT_CREATE_NOTES",
            ["mandiant", "create_notes"],
            config,
            default=False,
        )
        self.mandiant_remove_statement_marking = get_config_variable(
            "MANDIANT_REMOVE_STATEMENT_MARKING",
            ["mandiant", "remove_statement_marking"],
            config,
            default=False,
        )

        self.mandiant_marking = get_config_variable(
            "MANDIANT_MARKING",
            ["mandiant", "marking_definition"],
            config,
            default="AMBER+STRICT",
        )
        self._convert_tlp_to_marking_definition()

        self.mandiant_collections = []

        if get_config_variable(
            "MANDIANT_IMPORT_ACTORS",
            ["mandiant", "import_actors"],
            config,
            default=True,
        ):
            self.mandiant_collections.append("actors")

        mandiant_actors_interval = get_config_variable(
            "MANDIANT_IMPORT_ACTORS_INTERVAL",
            ["mandiant", "import_actors_interval"],
            config,
            isNumber=True,
            default=1,
        )
        self.mandiant_actors_interval = timedelta(hours=mandiant_actors_interval)

        self.mandiant_import_actors_aliases = get_config_variable(
            "MANDIANT_IMPORT_ACTORS_ALIASES",
            ["mandiant", "import_actors_aliases"],
            config,
            isNumber=False,
            default=False,
        )

        if get_config_variable(
            "MANDIANT_IMPORT_REPORTS",
            ["mandiant", "import_reports"],
            config,
            default=True,
        ):
            self.mandiant_collections.append("reports")

        mandiant_reports_interval = get_config_variable(
            "MANDIANT_IMPORT_REPORTS_INTERVAL",
            ["mandiant", "import_reports_interval"],
            config,
            isNumber=True,
            default=1,
        )
        self.mandiant_reports_interval = timedelta(hours=mandiant_reports_interval)

        if get_config_variable(
            "MANDIANT_IMPORT_MALWARES",
            ["mandiant", "import_malwares"],
            config,
            default=True,
        ):
            self.mandiant_collections.append("malwares")

        mandiant_malwares_interval = get_config_variable(
            "MANDIANT_IMPORT_MALWARES_INTERVAL",
            ["mandiant", "import_malwares_interval"],
            config,
            isNumber=True,
            default=1,
        )
        self.mandiant_malwares_interval = timedelta(hours=mandiant_malwares_interval)

        self.mandiant_import_malwares_aliases = get_config_variable(
            "MANDIANT_IMPORT_MALWARES_ALIASES",
            ["mandiant", "import_malwares_aliases"],
            config,
            isNumber=False,
            default=False,
        )

        if get_config_variable(
            "MANDIANT_IMPORT_CAMPAIGNS",
            ["mandiant", "import_campaigns"],
            config,
            default=True,
        ):
            self.mandiant_collections.append("campaigns")

        mandiant_campaigns_interval = get_config_variable(
            "MANDIANT_IMPORT_CAMPAIGNS_INTERVAL",
            ["mandiant", "import_campaigns_interval"],
            config,
            isNumber=True,
            default=1,
        )
        self.mandiant_campaigns_interval = timedelta(hours=mandiant_campaigns_interval)

        # When import indicators, import full campaigns (campaign details his related entities)
        self.import_indicators_with_full_campaigns = get_config_variable(
            "MANDIANT_IMPORT_INDICATORS_WITH_FULL_CAMPAIGNS",
            ["mandiant", "import_indicators_with_full_campaigns"],
            config,
            default=False,
        )

        if get_config_variable(
            "MANDIANT_IMPORT_INDICATORS",
            ["mandiant", "import_indicators"],
            config,
            default=True,
        ):
            self.mandiant_collections.append("indicators")

        mandiant_indicators_interval = get_config_variable(
            "MANDIANT_IMPORT_INDICATORS_INTERVAL",
            ["mandiant", "import_indicators_interval"],
            config,
            isNumber=True,
            default=1,
        )
        self.mandiant_indicators_interval = timedelta(
            hours=mandiant_indicators_interval
        )

        if get_config_variable(
            "MANDIANT_IMPORT_VULNERABILITIES",
            ["mandiant", "import_vulnerabilities"],
            config,
            default=False,
        ):
            self.mandiant_collections.append("vulnerabilities")

        mandiant_vulnerabilities_interval = get_config_variable(
            "MANDIANT_IMPORT_VULNERABILITIES_INTERVAL",
            ["mandiant", "import_vulnerabilities_interval"],
            config,
            isNumber=True,
            default=1,
        )
        self.mandiant_vulnerabilities_interval = timedelta(
            hours=mandiant_vulnerabilities_interval
        )

        self.mandiant_report_types = {}

        if get_config_variable(
            "MANDIANT_ACTOR_PROFILE_REPORT",
            ["mandiant", "actor_profile_report"],
            config,
            default=True,
        ):
            actor_profile_report_type = get_config_variable(
                "MANDIANT_ACTOR_PROFILE_REPORT_TYPE",
                ["mandiant", "actor_profile_report_type"],
                config,
                default="actor-profile",
            )
            self.mandiant_report_types["Actor Profile"] = actor_profile_report_type

        if get_config_variable(
            "MANDIANT_COUNTRY_PROFILE_REPORT",
            ["mandiant", "country_profile_report"],
            config,
            default=True,
        ):
            country_profile_report_type = get_config_variable(
                "MANDIANT_COUNTRY_PROFILE_REPORT_TYPE",
                ["mandiant", "country_profile_report_type"],
                config,
                default="country-profile",
            )
            self.mandiant_report_types["Country Profile"] = country_profile_report_type

        if get_config_variable(
            "MANDIANT_EVENT_COVERAGE_IMPLICATION_REPORT",
            ["mandiant", "event_coverage_implication_report"],
            config,
            default=True,
        ):
            event_coverage_implication_report_type = get_config_variable(
                "MANDIANT_EVENT_COVERAGE_IMPLICATION_REPORT_TYPE",
                ["mandiant", "event_coverage_implication_report_type"],
                config,
                default="event-coverage",
            )
            self.mandiant_report_types["Event Coverage/Implication"] = (
                event_coverage_implication_report_type
            )

        if get_config_variable(
            "MANDIANT_EXECUTIVE_PERSPECTIVE_REPORT",
            ["mandiant", "executive_perspective_report"],
            config,
            default=True,
        ):
            executive_perspective_report_type = get_config_variable(
                "MANDIANT_EXECUTIVE_PERSPECTIVE_REPORT_TYPE",
                ["mandiant", "executive_perspective_report_type"],
                config,
                default="executive-perspective",
            )
            self.mandiant_report_types["Executive Perspective"] = (
                executive_perspective_report_type
            )

        if get_config_variable(
            "MANDIANT_ICS_SECURITY_ROUNDUP_REPORT",
            ["mandiant", "ics_security_roundup_report"],
            config,
            default=True,
        ):
            ics_security_roundup_report_type = get_config_variable(
                "MANDIANT_ICS_SECURITY_ROUNDUP_REPORT_TYPE",
                ["mandiant", "ics_security_roundup_report_type"],
                config,
                default="ics-security-roundup",
            )
            self.mandiant_report_types["ICS Security Roundup"] = (
                ics_security_roundup_report_type
            )

        if get_config_variable(
            "MANDIANT_INDUSTRY_REPORTING_REPORT",
            ["mandiant", "industry_reporting_report"],
            config,
            default=True,
        ):
            industry_reporting_report_type = get_config_variable(
                "MANDIANT_INDUSTRY_REPORTING_REPORT_TYPE",
                ["mandiant", "industry_reporting_report_type"],
                config,
                default="industry",
            )
            self.mandiant_report_types["Industry Reporting"] = (
                industry_reporting_report_type
            )

        if get_config_variable(
            "MANDIANT_MALWARE_PROFILE_REPORT",
            ["mandiant", "malware_profile_report"],
            config,
            default=True,
        ):
            malware_profile_report_type = get_config_variable(
                "MANDIANT_MALWARE_PROFILE_REPORT_TYPE",
                ["mandiant", "malware_profile_report_type"],
                config,
                default="malware-profile",
            )
            self.mandiant_report_types["Malware Profile"] = malware_profile_report_type

        if get_config_variable(
            "MANDIANT_NETWORK_ACTIVITY_REPORT",
            ["mandiant", "network_activity_report"],
            config,
            default=True,
        ):
            network_activity_report_type = get_config_variable(
                "MANDIANT_NETWORK_ACTIVITY_REPORT_TYPE",
                ["mandiant", "network_activity_report_type"],
                config,
                default="network-activity",
            )
            self.mandiant_report_types["Network Activity Reports"] = (
                network_activity_report_type
            )

        if get_config_variable(
            "MANDIANT_PATCH_REPORT",
            ["mandiant", "patch_report"],
            config,
            default=True,
        ):
            patch_report_type = get_config_variable(
                "MANDIANT_PATCH_REPORT_TYPE",
                ["mandiant", "patch_report_type"],
                config,
                default="patch",
            )
            self.mandiant_report_types["Patch Report"] = patch_report_type

        if get_config_variable(
            "MANDIANT_TTP_DEEP_DIVE_REPORT",
            ["mandiant", "ttp_deep_dive_report"],
            config,
            default=True,
        ):
            ttp_deep_dive_report_type = get_config_variable(
                "MANDIANT_TTP_DEEP_DIVE_REPORT_TYPE",
                ["mandiant", "ttp_deep_dive_report_type"],
                config,
                default="ttp-deep-dive",
            )
            self.mandiant_report_types["TTP Deep Dive"] = ttp_deep_dive_report_type

        if get_config_variable(
            "MANDIANT_THREAT_ACTIVITY_ALERT_REPORT",
            ["mandiant", "threat_activity_alert_report"],
            config,
            default=True,
        ):
            threat_activity_alert_report_type = get_config_variable(
                "MANDIANT_THREAT_ACTIVITY_ALERT_REPORT_TYPE",
                ["mandiant", "threat_activity_alert_report_type"],
                config,
                default="threat-alert",
            )
            self.mandiant_report_types["Threat Activity Alert"] = (
                threat_activity_alert_report_type
            )

        if get_config_variable(
            "MANDIANT_THREAT_ACTIVITY_REPORT",
            ["mandiant", "threat_activity_report"],
            config,
            default=True,
        ):
            threat_activity_report_type = get_config_variable(
                "MANDIANT_THREAT_ACTIVITY_REPORT_TYPE",
                ["mandiant", "threat_activity_report_type"],
                config,
                default="threat-activity",
            )
            self.mandiant_report_types["Threat Activity Report"] = (
                threat_activity_report_type
            )

        if get_config_variable(
            "MANDIANT_TRENDS_AND_FORECASTING_REPORT",
            ["mandiant", "trends_and_forecasting_report"],
            config,
            default=True,
        ):
            trends_and_forecasting_report_type = get_config_variable(
                "MANDIANT_TRENDS_AND_FORECASTING_REPORT_TYPE",
                ["mandiant", "trends_and_forecasting_report_type"],
                config,
                default="trends-forecasting",
            )
            self.mandiant_report_types["Trends and Forecasting"] = (
                trends_and_forecasting_report_type
            )

        if get_config_variable(
            "MANDIANT_VULNERABILITY_REPORT",
            ["mandiant", "vulnerability_report"],
            config,
            default=True,
        ):
            vulnerability_report_type = get_config_variable(
                "MANDIANT_VULNERABILITY_REPORT_TYPE",
                ["mandiant", "vulnerability_report_type"],
                config,
                default="vulnerability",
            )
            self.mandiant_report_types["Vulnerability Report"] = (
                vulnerability_report_type
            )
        # Should be here!!!!
        self.mandiant_import_software_cpe = get_config_variable(
            "MANDIANT_VULNERABILITY_IMPORT_SOFTWARE_CPE",
            ["mandiant", "vulnerability_import_software_cpe"],
            config,
            default=True,
        )

        self.vulnerability_max_cpe_relationship = get_config_variable(
            "MANDIANT_VULNERABILITY_MAX_CPE_RELATIONSHIP",
            ["mandiant", "vulnerability_max_cpe_relationship"],
            config,
            default=200,
        )

        if get_config_variable(
            "MANDIANT_WEEKLY_VULNERABILITY_EXPLOITATION_REPORT",
            ["mandiant", "weekly_vulnerability_exploitation_report"],
            config,
            default=True,
        ):
            weekly_vulnerability_exploitation_report_type = get_config_variable(
                "MANDIANT_WEEKLY_VULNERABILITY_EXPLOITATION_REPORT_TYPE",
                ["mandiant", "weekly_vulnerability_exploitation_report_type"],
                config,
                default="vulnerability-exploitation",
            )
            self.mandiant_report_types["Weekly Vulnerability Exploitation Report"] = (
                weekly_vulnerability_exploitation_report_type
            )

        if get_config_variable(
            "MANDIANT_NEWS_ANALYSIS_REPORT",
            ["mandiant", "news_analysis_report"],
            config,
            default=True,
        ):
            news_analysis_report_type = get_config_variable(
                "MANDIANT_NEWS_ANALYSIS_REPORT_TYPE",
                ["mandiant", "news_analysis_report_type"],
                config,
                default="news-analysis",
            )
            self.mandiant_report_types["News Analysis"] = news_analysis_report_type

        try:
            for description, name in self.mandiant_report_types.items():
                self.helper.api.vocabulary.create(
                    name=name,
                    description=description,
                    category="report_types_ov",
                )
        except Exception as err:
            self.helper.connector_logger.warning(str(err))

        self.mandiant_indicator_minimum_score = get_config_variable(
            "MANDIANT_INDICATOR_MINIMUM_SCORE",
            ["mandiant", "indicator_minimum_score"],
            config,
            default=80,
        )

        self.identity = self.helper.api.identity.create(
            name="Mandiant",
            type="Organization",
        )

        self.api = MandiantAPI(
            self.helper,
            self.mandiant_api_v4_key_id,
            self.mandiant_api_v4_key_secret,
        )

        self._init_state()

    def compute_start_structure(self, start_date):
        now = Timestamp.now()
        start = Timestamp.from_iso(start_date)
        end = start.delta(days=self.mandiant_import_period)
        if end.value > now.value:
            end = None
        return {
            STATE_START: start.iso_format,
            STATE_END: end.iso_format if end is not None else None,
            STATE_LAST_RUN: now.iso_format,
            STATE_OFFSET: 0,
        }

    @staticmethod
    def _is_state_set(state: dict[str, Any] | None) -> bool:
        """Check if the state is set."""
        return not (
            state is None
            or state == {}
            or any(
                state.get(expected_key) is None
                for expected_key in [
                    "vulnerabilities",
                    "indicators",
                    "campaigns",
                    "malwares",
                    "reports",
                    "actors",
                ]
            )
        )

    def _init_state(self) -> dict[str, Any]:
        """Get State or reinitialize it if it is None.

        State is a Critical part of the connector, it is used to keep track of the last import for each collection and to paginate the API.

        """
        state = self.helper.get_state()
        if not Mandiant._is_state_set(state):
            # Create period of 1 day starting from the configuration
            # Mandiant API only paginate in reverse time ordering

            self.helper.connector_logger.warning(
                "State is None or incomplete, reinitializing it"
            )

            base_structure = self.compute_start_structure(
                self.mandiant_import_start_date
            )
            indicator_structure = self.compute_start_structure(
                self.mandiant_indicator_import_start_date
            )
            state = {
                "vulnerabilities": base_structure,
                "indicators": indicator_structure,
                "campaigns": base_structure,
                "malwares": base_structure,
                "reports": base_structure,
                "actors": base_structure,
            }
        self.helper.set_state(state)

    def get_state_value(self, collection_name: str, state_key: str) -> Any:
        """Using this method to get the value of a specific key in the state collection.

        It allows an external user to reset the state. The error is then handle gracefully to exit the current job.

        """
        try:
            return self.helper.get_state()[collection_name][state_key]
        except (KeyError, TypeError) as err:
            raise StateError(
                f"State key {state_key} not found in {collection_name} collection"
            ) from err

    def set_state_value(self, collection_name: str, state_key: str, value: Any):
        """Using this method to set the value of a specific key in the state collection.

        See Also:
            get_state_value
        """
        try:
            state = self.helper.get_state()
            state[collection_name][state_key] = value
            self.helper.set_state(state)
        except (KeyError, TypeError) as err:
            raise StateError(
                f"State key {state_key} not found in {collection_name} collection"
            ) from err

    def process_message(self):
        self._init_state()
        for collection in self.mandiant_collections:
            try:
                # Handle interval config
                date_now_value = Timestamp.now().value
                collection_interval = getattr(self, f"mandiant_{collection}_interval")

                last_run_value = Timestamp.from_iso(
                    self.get_state_value(
                        collection_name=collection, state_key=STATE_LAST_RUN
                    )
                ).value

                # API types related to simple offset
                collection_with_offset = ["malwares", "actors", "campaigns"]
                # Start and End, Offset
                start_offset = self.get_state_value(
                    collection_name=collection, state_key=STATE_OFFSET
                )
                end_offset = start_offset + OFFSET_PAGINATION

                # API types related to start_epoch
                collection_with_start_epoch = [
                    "reports",
                    "vulnerabilities",
                    "indicators",
                ]
                # Start and End, Timestamp short format
                start_date = Timestamp.from_iso(
                    self.get_state_value(
                        collection_name=collection, state_key=STATE_START
                    )
                )
                start_short_format = start_date.short_format

                # If no end date, put the proper period using delta
                if (
                    self.get_state_value(
                        collection_name=collection, state_key=STATE_END
                    )
                    is None
                ):
                    next_end = start_date.delta(days=self.mandiant_import_period)
                    # If delta is in the future, limit to today
                    if next_end.value > Timestamp.now().value:
                        next_end = Timestamp.now()
                    end_short_format = next_end.short_format
                else:
                    # Fix problem when end state is in the future
                    if (
                        Timestamp.from_iso(
                            self.get_state_value(
                                collection_name=collection, state_key=STATE_END
                            )
                        ).value
                        > Timestamp.now().value
                    ):
                        self.set_state_value(
                            collection_name=collection, state_key=STATE_END, value=None
                        )
                    end_short_format = Timestamp.from_iso(
                        self.get_state_value(
                            collection_name=collection, state_key=STATE_END
                        )
                    ).short_format

                # Additional information for the "work" depending on the collection (offset, epoch)
                start_work = (
                    start_short_format
                    if collection in collection_with_start_epoch
                    else start_offset
                )
                end_work = (
                    end_short_format
                    if collection in collection_with_start_epoch
                    else end_offset
                )

                import_start_date = (
                    self.mandiant_indicator_import_start_date
                    if collection == "indicators"
                    else self.mandiant_import_start_date
                )

                if collection in collection_with_start_epoch:
                    first_run = (
                        self.get_state_value(
                            collection_name=collection, state_key=STATE_START
                        )
                        == Timestamp.from_iso(import_start_date).iso_format
                    )
                else:
                    first_run = start_offset == 0

                # We check that after each API call the collection respects the interval,
                # either the default or the one specified in the config.
                # If it does not, we terminate the job and move on to the next collection.

                if (
                    first_run is False
                    and date_now_value - collection_interval < last_run_value
                ):
                    diff_time = round(
                        ((date_now_value - last_run_value).total_seconds()) / 60
                    )
                    remaining_time = round(
                        (
                            (
                                (
                                    collection_interval - timedelta(minutes=diff_time)
                                ).total_seconds()
                            )
                            / 60
                        )
                    )
                    self.helper.connector_logger.info(
                        f"Ignore the '{collection}' collection because the collection interval "
                        f"in the config is '{collection_interval}', the remaining time until the "
                        f"next collection pull: {remaining_time} min"
                    )
                    continue

                self.helper.connector_logger.info(
                    "Start collecting", {"collection": collection}
                )
                self._run(
                    collection,
                    collection_with_offset,
                    collection_with_start_epoch,
                    start_work,
                    end_work,
                )
                self.helper.connector_logger.info(
                    "Collection", {"collection": collection}
                )

            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info("Connector stop")
                sys.exit(0)

            except StateError as err:
                self.helper.connector_logger.error(
                    "Failed du to connector state error", {"error": str(err)}
                )
                break

            except Exception as e:
                self.helper.connector_logger.error(str(e))
                time.sleep(360)
                continue

    def run(self):
        self.helper.schedule_iso(
            message_callback=self.process_message, duration_period=self.duration_period
        )

    @staticmethod
    def remove_statement_marking(stix_objects: list) -> None:
        for obj in stix_objects:
            if "object_marking_refs" in obj:
                new_markings = []
                for ref in obj["object_marking_refs"]:
                    if ref not in STATEMENT_MARKINGS:
                        new_markings.append(ref)
                if len(new_markings) == 0:
                    del obj["object_marking_refs"]
                else:
                    obj["object_marking_refs"] = new_markings

    def _convert_tlp_to_marking_definition(self):
        """Get marking definition for given TLP."""
        if self.mandiant_marking is None:
            self.mandiant_marking = DEFAULT_TLP_MARKING_DEFINITION

        marking_definition = TLP_MARKING_DEFINITION_MAPPING.get(
            self.mandiant_marking.lower()
        )
        if marking_definition is None:
            raise ValueError(f"Invalid TLP value '{self.mandiant_marking}'")
        self.mandiant_marking = marking_definition

    def _process_batch_reports(
        self, new_batch_reports: list[Any], info_reports: dict[str, Any]
    ) -> None:
        """
          Process a batch of reports by deduplicating, cleaning, and submitting them.

        Args:
            new_batch_reports (list): The current batch of reports to process.
            info_reports (dict): Metadata and tracking information about the reports.

        Returns:
            None
        """
        try:
            bundles_objects_report = []

            for bundles_report in new_batch_reports:
                unique_bundles_report = self._deduplicate_and_clean_bundles(
                    bundles_report
                )
                bundles_objects_report.extend(unique_bundles_report)

            last_end_index = info_reports.get("start_batch_index_report") + len(
                new_batch_reports
            )
            info_reports.update(
                {
                    "end_batch_index_report": last_end_index,
                    "bundles_objects": bundles_objects_report,
                }
            )
            self._process_submission_report(info_reports)
            info_reports.update(
                {
                    "start_batch_index_report": last_end_index,
                }
            )
        except Exception as err:
            self.helper.connector_logger.error(
                "An error occurred during the report batch process",
                {"error": str(err), "info_reports": info_reports},
            )

    def _deduplicate_and_clean_bundles(self, bundles_objects: list[Any]) -> list:
        """
        Deduplicates and cleans STIX bundles.

        This method ensures that each object in the provided list of STIX bundles is unique based on its `id`.
        It also converts each STIX object to a dictionary format and optionally removes statement markings
        if the `mandiant_remove_statement_marking` variable environment is defined at true.

        Args:
            bundles_objects (list): A list of STIX objects to process.

        Returns:
            uniq_bundles_objects (list): A deduplicated and cleaned list of STIX objects in dictionary format.
        """
        try:
            uniq_bundles_objects = list(
                {obj["id"]: obj for obj in bundles_objects}.values()
            )
            # Transform objects to dicts
            uniq_bundles_objects = [
                json.loads(obj.serialize()) for obj in uniq_bundles_objects
            ]
            if self.mandiant_remove_statement_marking:
                uniq_bundles_objects = list(
                    filter(
                        lambda stix: stix["id"] not in STATEMENT_MARKINGS,
                        uniq_bundles_objects,
                    )
                )
                self.remove_statement_marking(uniq_bundles_objects)
            return uniq_bundles_objects
        except Exception as err:
            self.helper.connector_logger.error(
                "An error occurred during the deduplicate and clean bundles",
                {"error": str(err)},
            )

    def _process_submission_report(self, info_reports: dict[str, Any]) -> None:
        """
        Processes a submission report by creating a STIX bundle and marking the work as processed.

        This method initiates a work process, creates a STIX2 bundle from the provided data,
        sends the bundle, and marks the work as completed.

        Example:
            For an input dictionary like:

            info_reports = {
                "collection_title": "Reports",
                "start_work": "2024-11-20",
                "end_work": "2024-11-21",
                "start_batch_index_report": 0,
                "end_batch_index_report": 10,
                "bundles_objects": [...],  # List of STIX objects
            }

            The work ID will be initiated with the friendly_name (visible from the front):
            `"Reports 2024-11-20 - 2024-11-21 : 0 - 10"`.

        Args:
            info_reports (dict):
                - collection_title (str): The title of the collection being processed.
                - start_work (str): The start timestamp or identifier for the work.
                - end_work (str): The end timestamp or identifier for the work.
                - start_batch_index_report (int): The starting batch index of the report.
                - end_batch_index_report (int): The ending batch index of the report.
                - bundles_objects (list): A list of objects to include in the STIX2 bundle.

        Returns:
            None
        """
        report_work_id = None
        try:
            report_work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                f"{info_reports.get('collection_title')} "
                f"{info_reports.get('start_work')} - {info_reports.get('end_work')} : "
                f"{info_reports.get('start_batch_index_report')} - {info_reports.get('end_batch_index_report')}",
            )
            bundle = self.helper.stix2_create_bundle(
                info_reports.get("bundles_objects")
            )
            self.helper.send_stix2_bundle(
                bundle=bundle,
                work_id=report_work_id,
            )
            self.helper.api.work.to_processed(report_work_id, "Finished_report")
            report_work_id = None

        except Exception as err:
            self.helper.connector_logger.error(
                "An error occurred during the report submission process",
                {"error": str(err), "info_reports": info_reports},
            )
        finally:
            if report_work_id is not None:
                self.helper.api.work.to_processed(report_work_id, "Finished")

    def _run(
        self,
        collection,
        collection_with_offset,
        collection_with_start_epoch,
        start_work,
        end_work,
    ):
        work_id = None
        try:
            if collection != "reports":
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id,
                    f"{collection.title()} {start_work} - {end_work}",
                )
            module = importlib.import_module(f".{collection}", package=__package__)
            collection_api = getattr(self.api, collection)

            # If work in progress, then the new in progress will
            # be to start from the index until before_process_now. The current index
            # will also be updated to before_process_now to be used as a marker.

            before_process_now = Timestamp.now()

            start = Timestamp.from_iso(
                self.get_state_value(collection_name=collection, state_key=STATE_START)
            )

            # If no end date, put the proper period using delta
            if (
                self.get_state_value(collection_name=collection, state_key=STATE_END)
                is None
            ):
                end = start.delta(days=self.mandiant_import_period)
                # If delta is in the future, limit to today
                if end.value > Timestamp.now().value:
                    end = Timestamp.now()
            else:
                # Fix problem when end state is in the future
                if (
                    Timestamp.from_iso(
                        self.get_state_value(
                            collection_name=collection, state_key=STATE_END
                        )
                    ).value
                    > Timestamp.now().value
                ):
                    self.set_state_value(
                        collection_name=collection, state_key=STATE_END, value=None
                    )
                end = Timestamp.from_iso(
                    self.get_state_value(
                        collection_name=collection, state_key=STATE_END
                    )
                )

            offset = self.get_state_value(
                collection_name=collection, state_key=STATE_OFFSET
            )

            parameters = {}

            if collection in collection_with_offset:
                parameters[STATE_OFFSET] = offset

            elif collection in collection_with_start_epoch:
                parameters[STATE_START] = start.unix_format
                if collection == "indicators":
                    parameters["gte_mscore"] = self.mandiant_indicator_minimum_score
                if end is not None:
                    parameters[STATE_END] = end.unix_format

            else:
                self.helper.connector_logger.error(
                    f"The '{collection}' collection has not been correctly identified"
                )

            data = collection_api(**parameters)
            bundles_objects = []

            if "reports" in collection:

                new_batch_reports = []
                batch_report_size = BATCH_REPORT_SIZE

                info_reports = {
                    "collection_title": collection.title(),
                    "start_work": start_work,
                    "end_work": end_work,
                    "start_batch_index_report": 0,
                    "end_batch_index_report": batch_report_size,
                    "bundles_objects": [],
                }

                for item in data:
                    report_bundle = module.process(self, item)
                    if report_bundle:
                        new_batch_reports.append(report_bundle["objects"])

                    if len(new_batch_reports) == batch_report_size:
                        self._process_batch_reports(new_batch_reports, info_reports)
                        new_batch_reports = []

                if new_batch_reports:
                    # Handle the case where the last batch is incomplete based on batch_report_size
                    # Example batch_report_size = 10 and there are 13 reports
                    # The first batch contains 10 reports, and this part processes the remaining 3 reports
                    self._process_batch_reports(new_batch_reports, info_reports)

                else:
                    # If no data is available (user is up-to-date or no report exists at the connector launch date)
                    # Create a job with no operations to ensure consistent behavior with other collections
                    self.helper.connector_logger.info(
                        "No data has been imported for the report collection since the last run"
                    )
                    report_work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id,
                        f"{collection.title()} {start_work} - {end_work} : No data found",
                    )
                    self.helper.api.work.to_processed(report_work_id, "Finished_report")

            else:
                # This is where we manage all the other collections, apart from the Reports collection.
                for item in data:
                    bundle = module.process(self, item)
                    if bundle:
                        bundles_objects = bundles_objects + bundle["objects"]
                    offset += 1

                if len(bundles_objects) > 0:
                    unique_bundle_object = self._deduplicate_and_clean_bundles(
                        bundles_objects
                    )
                    bundle = self.helper.stix2_create_bundle(unique_bundle_object)
                    self.helper.send_stix2_bundle(
                        bundle,
                        work_id=work_id,
                    )
                    if collection in collection_with_offset:
                        self.set_state_value(
                            collection_name=collection,
                            state_key=STATE_OFFSET,
                            value=offset,
                        )
                else:
                    self.helper.connector_logger.info(
                        f"No data has been imported for the '{collection}' collection since the last run"
                    )

            if collection in collection_with_start_epoch:
                after_process_now = Timestamp.now()
                next_start = (
                    end if end is not None else before_process_now
                )  # next start is the previous end
                next_end = next_start.delta(days=self.mandiant_import_period)
                if next_end.value > after_process_now.value:
                    next_end = None
                self.set_state_value(
                    collection_name=collection,
                    state_key=STATE_START,
                    value=next_start.iso_format,
                )
                self.set_state_value(
                    collection_name=collection,
                    state_key=STATE_END,
                    value=next_end.iso_format if next_end is not None else None,
                )

            self.set_state_value(
                collection_name=collection,
                state_key=STATE_LAST_RUN,
                value=before_process_now.iso_format,
            )

        except StateError as err:
            self.helper.connector_logger.error(
                "Failed du to connector state error", {"error": str(err)}
            )
            if work_id is not None:
                self.helper.api.work.to_processed(
                    work_id, "Failed due to connector state error", in_error=True
                )
                work_id = None

        except Exception as err:
            self.helper.connector_logger.error(
                "An error occurred while processing the collection",
                {"collection": collection, "error": str(err)},
            )

        finally:
            if work_id is not None and collection != "reports":
                self.helper.api.work.to_processed(work_id, "Finished")
