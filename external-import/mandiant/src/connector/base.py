import importlib
import os
import sys
import time
import traceback
from datetime import datetime, timedelta

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .api import MandiantAPI
from .utils import Timestamp

STATE_START = "start_epoch"
STATE_OFFSET = "offset"
STATE_END = "end_epoch"
STATE_LAST_RUN = "last_run"


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
        self.mandiant_create_notes = get_config_variable(
            "MANDIANT_CREATE_NOTES",
            ["mandiant", "create_notes"],
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
            default=2,
        )
        self.mandiant_actors_interval = timedelta(hours=mandiant_actors_interval)

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
            default=96,
        )
        self.mandiant_malwares_interval = timedelta(hours=mandiant_malwares_interval)

        if get_config_variable(
            "MANDIANT_IMPORT_CAMPAIGNS",
            ["mandiant", "import_campaigns"],
            config,
            default=False,
        ):
            self.mandiant_collections.append("campaigns")

        mandiant_campaigns_interval = get_config_variable(
            "MANDIANT_IMPORT_CAMPAIGNS_INTERVAL",
            ["mandiant", "import_campaigns_interval"],
            config,
            isNumber=True,
            default=2,
        )
        self.mandiant_campaigns_interval = timedelta(hours=mandiant_campaigns_interval)

        if get_config_variable(
            "MANDIANT_IMPORT_INDICATORS",
            ["mandiant", "import_indicators"],
            config,
            default=False,
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
            self.mandiant_report_types[
                "Event Coverage/Implication"
            ] = event_coverage_implication_report_type

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
            self.mandiant_report_types[
                "Executive Perspective"
            ] = executive_perspective_report_type

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
            self.mandiant_report_types[
                "ICS Security Roundup"
            ] = ics_security_roundup_report_type

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
            self.mandiant_report_types[
                "Industry Reporting"
            ] = industry_reporting_report_type

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
            self.mandiant_report_types[
                "Network Activity Reports"
            ] = network_activity_report_type

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
            self.mandiant_report_types[
                "Threat Activity Alert"
            ] = threat_activity_alert_report_type

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
            self.mandiant_report_types[
                "Threat Activity Report"
            ] = threat_activity_report_type

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
            self.mandiant_report_types[
                "Trends and Forecasting"
            ] = trends_and_forecasting_report_type

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
            self.mandiant_report_types[
                "Vulnerability Report"
            ] = vulnerability_report_type

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
            self.mandiant_report_types[
                "Weekly Vulnerability Exploitation Report"
            ] = weekly_vulnerability_exploitation_report_type

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
        except Exception:
            self.helper.log_warning("Could not create report types.")

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
            self.mandiant_api_v4_key_id,
            self.mandiant_api_v4_key_secret,
        )

        if not self.helper.get_state():
            now = Timestamp.now()
            structure = {
                STATE_START: Timestamp.from_iso(
                    self.mandiant_import_start_date
                ).iso_format,
                STATE_OFFSET: 0,
                STATE_END: now.iso_format,
                STATE_LAST_RUN: Timestamp(now.value - timedelta(days=30)).iso_format,
            }
            self.helper.set_state(
                {
                    "vulnerabilities": structure,
                    "indicators": structure,
                    "campaigns": structure,
                    "malwares": structure,
                    "reports": structure,
                    "actors": structure,
                }
            )

    def run(self):
        for collection in self.mandiant_collections:
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                f"{collection.title()} {Timestamp.now().iso_format}",
            )

            now = Timestamp.now().value

            _last_run = self.helper.get_state()[collection][STATE_LAST_RUN]
            last_run = Timestamp.from_iso(_last_run).value

            interval = getattr(self, f"mandiant_{collection}_interval")

            if now - interval < last_run:
                self.helper.log_debug(
                    f"Skipping collecting {collection} due interval configuration..."
                )

            try:
                self.helper.log_info(f"Start collecting {collection} ...")
                self._run(collection, work_id)
                self.helper.log_info(f"Collection {collection} finished.")

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)

            except Exception as e:
                self.helper.log_error(str(e))
                self.helper.log_error(traceback.format_exc())
                time.sleep(360)
                continue

            finally:
                self.helper.api.work.to_processed(work_id, "Finished")

        if self.helper.connect_run_and_terminate:
            self.helper.log_info("Connector stop")
            self.helper.force_ping()
            sys.exit(0)

        time.sleep(self.mandiant_interval)

    def _run(self, collection, work_id):
        module = importlib.import_module(f".{collection}", package=__package__)
        collection_api = getattr(self.api, collection)
        state = self.helper.get_state()

        """
        If work in progress, then the new in progress will
        be to start from the index until now. The current index
        will also be updated to now to be used as a marker.
        """
        now = Timestamp.now()
        start = Timestamp.from_iso(state[collection][STATE_START])
        end = (
            Timestamp.now_minus_5_seconds()
        )  # Looks like Mandiant clock can be misaligned
        offset = state[collection][STATE_OFFSET]

        if STATE_END in state[collection] and state[collection][STATE_END] is not None:
            end = Timestamp.from_iso(state[collection][STATE_END])

        parameters = {}

        # API types related to start_epoch
        if collection == "reports":
            parameters[STATE_START] = start.unix_format
            parameters[STATE_END] = end.unix_format
            parameters[STATE_OFFSET] = offset
        if collection == "campaigns":
            parameters[STATE_START] = start.unix_format
            parameters[STATE_END] = end.unix_format
            parameters[STATE_OFFSET] = offset
        if collection == "vulnerabilities":
            parameters[STATE_START] = start.unix_format
            parameters[STATE_END] = end.unix_format
        if collection == "indicators":
            # Set 90 days maximum protection for indicator range
            if start.value < now.delta(days=-90).value:
                start = now.delta(days=-90)
            parameters[STATE_START] = start.unix_format
            parameters[STATE_END] = end.unix_format
            parameters["gte_mscore"] = self.mandiant_indicator_minimum_score

        # API types related to simple offset
        if collection == "malwares":
            parameters[STATE_OFFSET] = offset
        if collection == "actors":
            parameters[STATE_OFFSET] = offset

        computed_publish_date = None
        for item in collection_api(**parameters):
            if item is None:
                raise ValueError("[Error] Invalid Collection API")

            # Compute the last publish_date if the data
            if collection == "reports":
                publish_date = datetime.fromisoformat(item["publish_date"])
                computed_publish_date = (
                    max(computed_publish_date, publish_date)
                    if computed_publish_date is not None
                    else publish_date
                )
            elif collection == "vulnerabilities":
                publish_date = datetime.fromisoformat(item["publish_date"])
                computed_publish_date = (
                    max(computed_publish_date, publish_date)
                    if computed_publish_date is not None
                    else publish_date
                )
            elif collection == "indicators":
                last_updated = datetime.fromisoformat(item["last_updated"])
                computed_publish_date = (
                    max(computed_publish_date, last_updated)
                    if computed_publish_date is not None
                    else last_updated
                )
            elif collection == "campaigns":
                profile_updated = datetime.fromisoformat(item["profile_updated"])
                computed_publish_date = (
                    max(computed_publish_date, profile_updated)
                    if computed_publish_date is not None
                    else profile_updated
                )

            # Build and send the STIX bundle
            bundle = module.process(self, item)
            if bundle:
                self.helper.send_stix2_bundle(
                    bundle.serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )

            # Simple count / Increment the offset
            offset += 1

        if computed_publish_date is None:
            last_publish_date = now.iso_format
        else:
            last_publish_date = computed_publish_date.isoformat()

        if collection == "reports":
            state[collection][STATE_START] = last_publish_date
            state[collection][STATE_END] = None
            state[collection][STATE_OFFSET] = 0
            state[collection][STATE_LAST_RUN] = now.iso_format

        if collection == "campaigns":
            state[collection][STATE_START] = last_publish_date
            state[collection][STATE_END] = None
            state[collection][STATE_OFFSET] = 0
            state[collection][STATE_LAST_RUN] = now.iso_format

        if collection == "malwares":
            state[collection][STATE_OFFSET] = offset
            state[collection][STATE_LAST_RUN] = now.iso_format

        if collection == "actors":
            state[collection][STATE_OFFSET] = offset
            state[collection][STATE_LAST_RUN] = now.iso_format

        if collection == "vulnerabilities":
            state[collection][STATE_START] = last_publish_date
            state[collection][STATE_END] = None
            state[collection][STATE_LAST_RUN] = now.iso_format

        if collection == "indicators":
            state[collection][STATE_START] = end.iso_format
            state[collection][STATE_END] = None
            state[collection][STATE_LAST_RUN] = now.iso_format

        self.helper.set_state(state)
