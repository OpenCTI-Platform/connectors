import importlib
import sys
import time
import traceback

from mandiant.api import MandiantAPI
from mandiant.utils import Timestamp
from pycti import OpenCTIConnectorHelper, get_config_variable

STATE_START = "start_epoch"
STATE_OFFSET = "offset"
STATE_END = "end_epoch"


class Mandiant:
    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
        )
        self.mandiant_api_v4_key_id = get_config_variable(
            "MANDIANT_API_V4_KEY_ID",
            ["mandiant", "api_v4_key_id"],
        )
        self.mandiant_api_v4_key_secret = get_config_variable(
            "MANDIANT_API_V4_KEY_SECRET",
            ["mandiant", "api_v4_key_secret"],
        )
        self.mandiant_interval = get_config_variable(
            "MANDIANT_INTERVAL",
            ["mandiant", "interval"],
            isNumber=True,
            default=120,
        )
        self.mandiant_import_start_date = get_config_variable(
            "MANDIANT_IMPORT_START_DATE",
            ["mandiant", "import_start_date"],
            default="2023-01-01",
        )

        self.mandiant_collections = []

        if get_config_variable(
            "MANDIANT_IMPORT_ACTORS",
            ["mandiant", "import_actors"],
            default=True,
        ):
            self.mandiant_collections.append("actors")

        if get_config_variable(
            "MANDIANT_IMPORT_REPORTS",
            ["mandiant", "import_reports"],
            default=True,
        ):
            self.mandiant_collections.append("reports")

        if get_config_variable(
            "MANDIANT_IMPORT_MALWARES",
            ["mandiant", "import_malwares"],
            default=True,
        ):
            self.mandiant_collections.append("malwares")

        if get_config_variable(
            "MANDIANT_IMPORT_CAMPAIGNS",
            ["mandiant", "import_campaigns"],
            default=False,
        ):
            self.mandiant_collections.append("campaigns")

        if get_config_variable(
            "MANDIANT_IMPORT_INDICATORS",
            ["mandiant", "import_indicators"],
            default=True,
        ):
            self.mandiant_collections.append("indicators")

        if get_config_variable(
            "MANDIANT_IMPORT_VULNERABILITIES",
            ["mandiant", "import_vulnerabilities"],
            default=True,
        ):
            self.mandiant_collections.append("vulnerabilities")

        self.mandiant_report_types = {}

        if get_config_variable(
            "MANDIANT_ACTOR_PROFILE_REPORT",
            ["mandiant", "actor_profile_report"],
            default=True,
        ):
            actor_profile_report_type = get_config_variable(
                "MANDIANT_ACTOR_PROFILE_REPORT_TYPE",
                ["mandiant", "actor_profile_report_type"],
                default="actor-profile",
            )
            self.mandiant_report_types["Actor Profile"] = actor_profile_report_type

        if get_config_variable(
            "MANDIANT_COUNTRY_PROFILE_REPORT",
            ["mandiant", "country_profile_report"],
            default=True,
        ):
            country_profile_report_type = get_config_variable(
                "MANDIANT_COUNTRY_PROFILE_REPORT_TYPE",
                ["mandiant", "country_profile_report_type"],
                default="country-profile",
            )
            self.mandiant_report_types["Country Profile"] = country_profile_report_type

        if get_config_variable(
            "MANDIANT_EVENT_COVERAGE_IMPLICATION_REPORT",
            ["mandiant", "event_coverage_implication_report"],
            default=True,
        ):
            event_coverage_implication_report_type = get_config_variable(
                "MANDIANT_EVENT_COVERAGE_IMPLICATION_REPORT_TYPE",
                ["mandiant", "event_coverage_implication_report_type"],
                default="event-coverage",
            )
            self.mandiant_report_types[
                "Event Coverage/Implication"
            ] = event_coverage_implication_report_type

        if get_config_variable(
            "MANDIANT_EXECUTIVE_PERSPECTIVE_REPORT",
            ["mandiant", "executive_perspective_report"],
            default=True,
        ):
            executive_perspective_report_type = get_config_variable(
                "MANDIANT_EXECUTIVE_PERSPECTIVE_REPORT_TYPE",
                ["mandiant", "executive_perspective_report_type"],
                default="executive-perspective",
            )
            self.mandiant_report_types[
                "Executive Perspective"
            ] = executive_perspective_report_type

        if get_config_variable(
            "MANDIANT_ICS_SECURITY_ROUNDUP_REPORT",
            ["mandiant", "ics_security_roundup_report"],
            default=True,
        ):
            ics_security_roundup_report_type = get_config_variable(
                "MANDIANT_ICS_SECURITY_ROUNDUP_REPORT_TYPE",
                ["mandiant", "ics_security_roundup_report_type"],
                default="ics-security-roundup",
            )
            self.mandiant_report_types[
                "ICS Security Roundup"
            ] = ics_security_roundup_report_type

        if get_config_variable(
            "MANDIANT_INDUSTRY_REPORTING_REPORT",
            ["mandiant", "industry_reporting_report"],
            default=True,
        ):
            industry_reporting_report_type = get_config_variable(
                "MANDIANT_INDUSTRY_REPORTING_REPORT_TYPE",
                ["mandiant", "industry_reporting_report_type"],
                default="industry",
            )
            self.mandiant_report_types[
                "Industry Reporting"
            ] = industry_reporting_report_type

        if get_config_variable(
            "MANDIANT_MALWARE_PROFILE_REPORT",
            ["mandiant", "malware_profile_report"],
            default=True,
        ):
            malware_profile_report_type = get_config_variable(
                "MANDIANT_MALWARE_PROFILE_REPORT_TYPE",
                ["mandiant", "malware_profile_report_type"],
                default="malware-profile",
            )
            self.mandiant_report_types["Malware Profile"] = malware_profile_report_type

        if get_config_variable(
            "MANDIANT_NETWORK_ACTIVITY_REPORT",
            ["mandiant", "network_activity_report"],
            default=True,
        ):
            network_activity_report_type = get_config_variable(
                "MANDIANT_NETWORK_ACTIVITY_REPORT_TYPE",
                ["mandiant", "network_activity_report_type"],
                default="network-activity",
            )
            self.mandiant_report_types[
                "Network Activity Reports"
            ] = network_activity_report_type

        if get_config_variable(
            "MANDIANT_PATCH_REPORT",
            ["mandiant", "patch_report"],
            default=True,
        ):
            patch_report_type = get_config_variable(
                "MANDIANT_PATCH_REPORT_TYPE",
                ["mandiant", "patch_report_type"],
                default="patch",
            )
            self.mandiant_report_types["Patch Report"] = patch_report_type

        if get_config_variable(
            "MANDIANT_TTP_DEEP_DIVE_REPORT",
            ["mandiant", "ttp_deep_dive_report"],
            default=True,
        ):
            ttp_deep_dive_report_type = get_config_variable(
                "MANDIANT_TTP_DEEP_DIVE_REPORT_TYPE",
                ["mandiant", "ttp_deep_dive_report_type"],
                default="ttp-deep-dive",
            )
            self.mandiant_report_types["TTP Deep Dive"] = ttp_deep_dive_report_type

        if get_config_variable(
            "MANDIANT_THREAT_ACTIVITY_ALERT_REPORT",
            ["mandiant", "threat_activity_alert_report"],
            default=True,
        ):
            threat_activity_alert_report_type = get_config_variable(
                "MANDIANT_THREAT_ACTIVITY_ALERT_REPORT_TYPE",
                ["mandiant", "threat_activity_alert_report_type"],
                default="threat-alert",
            )
            self.mandiant_report_types[
                "Threat Activity Alert"
            ] = threat_activity_alert_report_type

        if get_config_variable(
            "MANDIANT_THREAT_ACTIVITY_REPORT",
            ["mandiant", "threat_activity_report"],
            default=True,
        ):
            threat_activity_report_type = get_config_variable(
                "MANDIANT_THREAT_ACTIVITY_REPORT_TYPE",
                ["mandiant", "threat_activity_report_type"],
                default="threat-activity",
            )
            self.mandiant_report_types[
                "Threat Activity Report"
            ] = threat_activity_report_type

        if get_config_variable(
            "MANDIANT_TRENDS_AND_FORECASTING_REPORT",
            ["mandiant", "trends_and_forecasting_report"],
            default=True,
        ):
            trends_and_forecasting_report_type = get_config_variable(
                "MANDIANT_TRENDS_AND_FORECASTING_REPORT_TYPE",
                ["mandiant", "trends_and_forecasting_report_type"],
                default="trends-forecasting",
            )
            self.mandiant_report_types[
                "Trends and Forecasting"
            ] = trends_and_forecasting_report_type

        if get_config_variable(
            "MANDIANT_VULNERABILITY_REPORT",
            ["mandiant", "vulnerability_report"],
            default=True,
        ):
            vulnerability_report_type = get_config_variable(
                "MANDIANT_VULNERABILITY_REPORT_TYPE",
                ["mandiant", "vulnerability_report_type"],
                default="vulnerability",
            )
            self.mandiant_report_types[
                "Vulnerability Report"
            ] = vulnerability_report_type

        if get_config_variable(
            "MANDIANT_WEEKLY_VULNERABILITY_EXPLOITATION_REPORT",
            ["mandiant", "weekly_vulnerability_exploitation_report"],
            default=True,
        ):
            weekly_vulnerability_exploitation_report_type = get_config_variable(
                "MANDIANT_WEEKLY_VULNERABILITY_EXPLOITATION_REPORT_TYPE",
                ["mandiant", "weekly_vulnerability_exploitation_report_type"],
                default="vulnerability-exploitation",
            )
            self.mandiant_report_types[
                "Weekly Vulnerability Exploitation Report"
            ] = weekly_vulnerability_exploitation_report_type

        if get_config_variable(
            "MANDIANT_NEWS_ANALYSIS_REPORT",
            ["mandiant", "news_analysis_report"],
            default=False,
        ):
            news_analysis_report_type = get_config_variable(
                "MANDIANT_NEWS_ANALYSIS_REPORT_TYPE",
                ["mandiant", "news_analysis_report_type"],
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
            default=80,
        )

        self.mandiant_interval = int(self.mandiant_interval) * 60

        self.identity = self.helper.api.identity.create(
            name="Mandiant, Inc.",
            type="Organization",
        )

        self.api = MandiantAPI(
            self.mandiant_api_v4_key_id, self.mandiant_api_v4_key_secret
        )

        if not self.helper.get_state():
            now = Timestamp.now()
            structure = {
                STATE_START: Timestamp.from_iso(
                    self.mandiant_import_start_date
                ).iso_format,
                STATE_OFFSET: 0,
                STATE_END: now.iso_format,
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
                f"{collection.title()} {Timestamp.now().iso_format} - {Timestamp.now().iso_format}",
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
        end = Timestamp.now()
        offset = state[collection][STATE_OFFSET]

        if STATE_END in state[collection] and state[collection][STATE_END] is not None:
            end = Timestamp.from_iso(state[collection][STATE_END])

        parameters = {}

        if collection == "reports":
            parameters[STATE_START] = start.unix_format
            parameters[STATE_END] = end.unix_format
            parameters[STATE_OFFSET] = offset

        if collection == "campaigns":
            parameters[STATE_START] = start.unix_format
            parameters[STATE_END] = end.unix_format
            parameters[STATE_OFFSET] = offset

        if collection == "malwares":
            parameters[STATE_OFFSET] = offset

        if collection == "actors":
            parameters[STATE_OFFSET] = offset

        if collection == "vulnerabilities":
            parameters[STATE_START] = start.unix_format
            parameters[STATE_END] = end.unix_format
            parameters["sort_order"] = "asc"

        if collection == "indicators":
            end = now
            if start.value < now.delta(days=-90).value:
                start = now.delta(days=-90)
            parameters[STATE_START] = start.unix_format
            parameters[STATE_END] = end.unix_format
            parameters["gte_mscore"] = self.mandiant_indicator_minimum_score

        try:
            for item in collection_api(**parameters):
                bundle = module.process(self, item)

                if bundle:
                    self.helper.send_stix2_bundle(
                        bundle.serialize(),
                        update=self.update_existing_data,
                        work_id=work_id,
                    )

                offset += 1

        except (KeyboardInterrupt, SystemExit, BaseException) as error:
            """
            Save current state before exitting in order to provide
            the capability to start near the moment where it exitted.
            """
            if collection == "vulnerabilities":
                state[collection][STATE_START] = item["publish_date"]
            elif collection == "indicators":
                pass
            else:
                state[collection][STATE_OFFSET] = offset

            self.helper.set_state(state)
            self.helper.log_info("Saving state ...")
            time.sleep(2)
            raise error

        if collection == "reports":
            state[collection][STATE_START] = end.iso_format
            state[collection][STATE_END] = None
            state[collection][STATE_OFFSET] = 0

        if collection == "campaigns":
            state[collection][STATE_START] = end.iso_format
            state[collection][STATE_END] = None
            state[collection][STATE_OFFSET] = 0

        if collection == "malwares":
            state[collection][STATE_OFFSET] = offset

        if collection == "actors":
            state[collection][STATE_OFFSET] = offset

        if collection == "vulnerabilities":
            state[collection][STATE_START] = end.iso_format
            state[collection][STATE_END] = None

        if collection == "indicators":
            state[collection][STATE_START] = end.iso_format
            state[collection][STATE_END] = None

        self.helper.set_state(state)
