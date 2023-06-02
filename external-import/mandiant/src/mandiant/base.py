import traceback
import importlib
import time
import json
import sys

from pycti import OpenCTIConnectorHelper, get_config_variable

from mandiant.api import MandiantAPI
from mandiant.utils import Timestamp


STATE_START = "start_epoch"
STATE_OFFSET = "offset"
STATE_END = "end_epoch"


# TODO:
# - handle campaigns
# - set different intervals for each collection


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

        self.mandiant_report_types = []

        if get_config_variable(
            "MANDIANT_ACTOR_PROFILE_REPORT",
            ["mandiant", "actor_profile_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Actor Profile")

        if get_config_variable(
            "MANDIANT_COUNTRY_PROFILE_REPORT",
            ["mandiant", "country_profile_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Country Profile")

        if get_config_variable(
            "MANDIANT_EVENT_COVERAGE_IMPLICATION_REPORT",
            ["mandiant", "event_coverage_implication_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Event Coverage/Implication")

        if get_config_variable(
            "MANDIANT_EXECUTIVE_PERSPECTIVE_REPORT",
            ["mandiant", "executive_perspective_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Executive Perspective")

        if get_config_variable(
            "MANDIANT_ICS_SECURITY_ROUNDUP_REPORT",
            ["mandiant", "ics_security_roundup_report"],
            default=True,
        ):
            self.mandiant_report_types.append("ICS Security Roundup")

        if get_config_variable(
            "MANDIANT_INDUSTRY_REPORTING_REPORT",
            ["mandiant", "industry_reporting_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Industry Reporting")

        if get_config_variable(
            "MANDIANT_MALWARE_PROFILE_REPORT",
            ["mandiant", "malware_profile_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Malware Profile")

        if get_config_variable(
            "MANDIANT_NETWORK_ACTIVITY_REPORT",
            ["mandiant", "network_activity_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Network Activity Reports")

        if get_config_variable(
            "MANDIANT_PATCH_REPORT",
            ["mandiant", "patch_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Patch Report")

        if get_config_variable(
            "MANDIANT_TTP_DEEP_DIVE_REPORT",
            ["mandiant", "ttp_deep_dive_report"],
            default=True,
        ):
            self.mandiant_report_types.append("TTP Deep Dive")

        if get_config_variable(
            "MANDIANT_THREAT_ACTIVITY_ALERT_REPORT",
            ["mandiant", "threat_activity_alert_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Threat Activity Alert")

        if get_config_variable(
            "MANDIANT_THREAT_ACTIVITY_REPORT",
            ["mandiant", "threat_activity_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Threat Activity Report")

        if get_config_variable(
            "MANDIANT_TRENDS_AND_FORECASTING_REPORT",
            ["mandiant", "trends_and_forecasting_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Trends and Forecasting")

        if get_config_variable(
            "MANDIANT_VULNERABILITY_REPORT",
            ["mandiant", "vulnerability_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Vulnerability Report")

        if get_config_variable(
            "MANDIANT_WEEKLY_VULNERABILITY_EXPLOITATION_REPORT",
            ["mandiant", "weekly_vulnerability_exploitation_report"],
            default=True,
        ):
            self.mandiant_report_types.append("Weekly Vulnerability Exploitation Report")

        if get_config_variable(
            "MANDIANT_NEWS_ANALYSIS_REPORT",
            ["mandiant", "news_analysis_report"],
            default=False,
        ):
            self.mandiant_report_types.append("News Analysis")

        self.mandiant_indicator_minimum_score = get_config_variable(
            "MANDIANT_INDICATOR_MINIMUM_SCORE",
            ["mandiant", "indicator_minimum_score"],
            default=80,
        )

        self.mandiant_interval = int(self.mandiant_interval) * 60

        self.identity = self.helper.api.identity.create(
            id="identity--28dc7d92-5db5-57d8-9c82-e151d743bb93",
            type="Organization",
            name="Mandiant, Inc.",
        )

        self.api = MandiantAPI(self.mandiant_api_v4_key_id, self.mandiant_api_v4_key_secret)

        if not self.helper.get_state():
            now = Timestamp.now()
            structure = {
                STATE_START: Timestamp.from_iso(self.mandiant_import_start_date).iso_format,
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
            for offset, item in enumerate(collection_api(**parameters)):
                bundle = module.process(self, item)

                if not bundle:
                    continue

                self.helper.send_stix2_bundle(
                    bundle.serialize(),
                    update=self.update_existing_data,
                    work_id=work_id,
                )

        except BaseException as error:
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
