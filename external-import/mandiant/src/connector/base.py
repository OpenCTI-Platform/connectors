import importlib
import json
import os
import sys
import time
from datetime import timedelta

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .api import OFFSET_PAGINATION, MandiantAPI
from .utils import Timestamp

STATE_START = "start_epoch"
STATE_OFFSET = "offset"
STATE_END = "end_epoch"
STATE_LAST_RUN = "last_run"

STATEMENT_MARKINGS = [
    "marking-definition--ad2caa47-58fd-5491-8f67-255377927369",
]


class Mandiant:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
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
            default=3,
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

        self.mandiant_interval = int(timedelta(minutes=5).total_seconds())

        self.identity = self.helper.api.identity.create(
            name="Mandiant",
            type="Organization",
        )

        self.api = MandiantAPI(
            self.helper,
            self.mandiant_api_v4_key_id,
            self.mandiant_api_v4_key_secret,
        )

        if not self.helper.get_state():
            # Create period of 1 day starting from the configuration
            # Mandiant API only paginate in reverse time ordering
            base_structure = self.compute_start_structure(
                self.mandiant_import_start_date
            )
            indicator_structure = self.compute_start_structure(
                self.mandiant_indicator_import_start_date
            )
            self.helper.set_state(
                {
                    "vulnerabilities": base_structure,
                    "indicators": indicator_structure,
                    "campaigns": base_structure,
                    "malwares": base_structure,
                    "reports": base_structure,
                    "actors": base_structure,
                }
            )

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

    def run(self):
        state = self.helper.get_state()
        for collection in self.mandiant_collections:
            # Handle interval config
            date_now_value = Timestamp.now().value
            collection_interval = getattr(self, f"mandiant_{collection}_interval")
            last_run_value = Timestamp.from_iso(state[collection][STATE_LAST_RUN]).value

            # API types related to simple offset
            collection_with_offset = ["malwares", "actors", "campaigns"]
            # Start and End, Offset
            start_offset = state[collection][STATE_OFFSET]
            end_offset = start_offset + OFFSET_PAGINATION

            # API types related to start_epoch
            collection_with_start_epoch = ["reports", "vulnerabilities", "indicators"]
            # Start and End, Timestamp short format
            start_short_format = Timestamp.from_iso(
                state[collection][STATE_START]
            ).short_format
            end_short_format = (
                Timestamp.from_iso(state[collection][STATE_END]).short_format
                if state[collection][STATE_END] is not None
                else Timestamp.now().short_format
            )

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
                    True
                    if state[collection][STATE_START]
                    == Timestamp.from_iso(import_start_date).iso_format
                    else False
                )
            else:
                first_run = True if start_offset == 0 else False

            """
            We check that after each API call the collection respects the interval, 
            either the default or the one specified in the config.
            If it does not, we terminate the job and move on to the next collection.
            """

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
                    f"Ignore the '{collection}' collection because the collection interval in the config is '{collection_interval}', the remaining time for the next run : {remaining_time} min"
                )
                continue

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                f"{collection.title()} {start_work} - {end_work}",
            )
            try:
                self.helper.connector_logger.info(
                    "Start collecting", {"collection": collection}
                )
                self._run(
                    work_id,
                    collection,
                    state,
                    collection_with_offset,
                    collection_with_start_epoch,
                )
                self.helper.connector_logger.info(
                    "Collection", {"collection": collection}
                )

            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info("Connector stop")
                sys.exit(0)

            except Exception as e:
                self.helper.connector_logger.error(str(e))
                time.sleep(360)
                continue

            finally:
                self.helper.api.work.to_processed(work_id, "Finished")

        if self.helper.connect_run_and_terminate:
            self.helper.connector_logger.info("Connector stop")
            self.helper.force_ping()
            sys.exit(0)

        time.sleep(self.mandiant_interval)

    def remove_statement_marking(self, stix_objects):
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

    def _run(
        self,
        work_id,
        collection,
        state,
        collection_with_offset,
        collection_with_start_epoch,
    ):
        module = importlib.import_module(f".{collection}", package=__package__)
        collection_api = getattr(self.api, collection)

        """
        If work in progress, then the new in progress will
        be to start from the index until before_process_now. The current index
        will also be updated to before_process_now to be used as a marker.
        """
        before_process_now = Timestamp.now()
        start = Timestamp.from_iso(state[collection][STATE_START])
        end = (
            Timestamp.from_iso(state[collection][STATE_END])
            if state[collection][STATE_END] is not None
            else None
        )
        offset = state[collection][STATE_OFFSET]

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
        for item in data:
            bundle = module.process(self, item)
            if bundle:
                bundles_objects = bundles_objects + bundle["objects"]
            offset += 1

        if len(bundles_objects) > 0:
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

            bundle = self.helper.stix2_create_bundle(uniq_bundles_objects)
            self.helper.send_stix2_bundle(
                bundle,
                update=self.update_existing_data,
                work_id=work_id,
            )
            if collection in collection_with_offset:
                state[collection][STATE_OFFSET] = offset
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
            state[collection][STATE_START] = next_start.iso_format
            state[collection][STATE_END] = (
                next_end.iso_format if next_end is not None else None
            )
        state[collection][STATE_LAST_RUN] = before_process_now.iso_format
        self.helper.set_state(state)
