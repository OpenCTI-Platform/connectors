import traceback
import importlib
import time
import json
import sys

from pycti import OpenCTIConnectorHelper, get_config_variable

from mandiant.api import MandiantAPI
from mandiant.utils import Timestamp


STATE_START = "start"
STATE_OFFSET = "offset"
STATE_END = "end"


class Mandiant:
    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

        self.update_existing_data = get_config_variable("CONNECTOR_UPDATE_EXISTING_DATA", [""])

        self.mandiant_api_v4_key_id = get_config_variable("MANDIANT_API_V4_KEY_ID", [""])

        self.mandiant_api_v4_key_secret = get_config_variable("MANDIANT_API_V4_KEY_SECRET", [""])

        self.mandiant_interval = get_config_variable("MANDIANT_INTERVAL", [""], isNumber=True, default=120)  # minutes

        self.mandiant_import_start_date = get_config_variable("MANDIANT_IMPORT_START_DATE", [""], default="2023-01-01")

        self.mandiant_collections = []
        if get_config_variable("MANDIANT_IMPORT_ACTORS", [""], default=True):
            self.mandiant_collections.append("actors")
        if get_config_variable("MANDIANT_IMPORT_REPORTS", [""], default=True):
            self.mandiant_collections.append("reports")
        if get_config_variable("MANDIANT_IMPORT_MALWARES", [""], default=True):
            self.mandiant_collections.append("malwares")
        # TODO: work on this collection (current default is False)
        if get_config_variable("MANDIANT_IMPORT_CAMPAIGNS", [""], default=False):
            self.mandiant_collections.append("campaigns")
        if get_config_variable("MANDIANT_IMPORT_INDICATORS", [""], default=True):
            self.mandiant_collections.append("indicators")
        if get_config_variable("MANDIANT_IMPORT_VULNERABILITIES", [""], default=True):
            self.mandiant_collections.append("vulnerabilities")

        self.mandiant_report_types = []
        if get_config_variable("MANDIANT_ACTOR_PROFILE", [""], default=True):
            self.mandiant_report_types.append("Actor Profile")
        if get_config_variable("MANDIANT_COUNTRY_PROFILE", [""], default=True):
            self.mandiant_report_types.append("Country Profile")
        if get_config_variable("MANDIANT_EVENT_COVERAGE_IMPLICATION", [""], default=True):
            self.mandiant_report_types.append("Event Coverage/Implication")
        if get_config_variable("MANDIANT_EXECUTIVE_PERSPECTIVE", [""], default=True):
            self.mandiant_report_types.append("Executive Perspective")
        if get_config_variable("MANDIANT_ICS_SECURITY_ROUNDUP", [""], default=True):
            self.mandiant_report_types.append("ICS Security Roundup")
        if get_config_variable("MANDIANT_INDUSTRY_REPORTING", [""], default=True):
            self.mandiant_report_types.append("Industry Reporting")
        if get_config_variable("MANDIANT_MALWARE_PROFILE", [""], default=True):
            self.mandiant_report_types.append("Malware Profile")
        if get_config_variable("MANDIANT_NETWORK_ACTIVITY_REPORTS", [""], default=True):
            self.mandiant_report_types.append("Network Activity Reports")
        if get_config_variable("MANDIANT_PATCH_REPORT", [""], default=True):
            self.mandiant_report_types.append("Patch Report")
        if get_config_variable("MANDIANT_TTP_DEEP_DIVE", [""], default=True):
            self.mandiant_report_types.append("TTP Deep Dive")
        if get_config_variable("MANDIANT_THREAT_ACTIVITY_ALERT", [""], default=True):
            self.mandiant_report_types.append("Threat Activity Alert")
        if get_config_variable("MANDIANT_THREAT_ACTIVITY_REPORT", [""], default=True):
            self.mandiant_report_types.append("Threat Activity Report")
        if get_config_variable("MANDIANT_TRENDS_AND_FORECASTING", [""], default=True):
            self.mandiant_report_types.append("Trends and Forecasting")
        if get_config_variable("MANDIANT_VULNERABILITY_REPORT", [""], default=True):
            self.mandiant_report_types.append("Vulnerability Report")
        if get_config_variable("MANDIANT_WEEKLY_VULNERABILITY_EXPLOITATION_REPORT", [""], default=True):
            self.mandiant_report_types.append("Weekly Vulnerability Exploitation Report")
        # TODO: work on this report (current default is False)
        if get_config_variable("MANDIANT_NEWS_ANALYSIS", [""], default=False):
            self.mandiant_report_types.append("News Analysis")

        self.mandiant_indicator_minimum_score = get_config_variable(
            "MANDIANT_INDICATOR_MINIMUM_SCORE", [""], default=80
        )

        # FIXME: set different intervals for each collection
        self.mandiant_interval = int(self.mandiant_interval) * 60

        self.identity = self.helper.api.identity.create(
            id="identity--28dc7d92-5db5-57d8-9c82-e151d743bb93",
            type="Organization",
            name="Mandiant, Inc",
        )

        self.api = MandiantAPI(self.mandiant_api_v4_key_id, self.mandiant_api_v4_key_secret)

        if not self.helper.get_state():
            now = Timestamp.now()
            structure = {
                STATE_START: Timestamp.from_iso(self.mandiant_import_start_date).iso_format,
                STATE_OFFSET: 0,
                STATE_END: now.iso_format,
            }
            self.helper.set_state({
                "vulnerabilities": structure,
                "indicators": structure,
                "campaigns": structure,
                "malwares": structure,
                "reports": structure,
                "actors": structure,
            })

    def _run(self, collection, work_id):
        module = importlib.import_module(f".{collection}", package=__package__)
        collection_api = getattr(self.api, collection)
        state = self.helper.get_state()

        '''
        If work in progress, then the new in progress will
        be to start from the index until now. The current index
        will also be updated to now to be used as a marker.
        '''
        now = Timestamp.now()

        start = Timestamp.from_iso(state[collection][STATE_START])
        end = Timestamp.from_iso(state[collection].get(STATE_END, now.iso_format))
        offset = state[collection][STATE_OFFSET]

        parameters = {}

        if collection == "reports":
            parameters["start_epoch"] = start.unix_format
            parameters["end_epoch"] = end.unix_format
            parameters["offset"] = offset

        if collection == "campaigns":
            parameters["start_epoch"] = start.unix_format
            parameters["end_epoch"] = end.unix_format
            parameters["offset"] = offset

        if collection == "malwares":
            parameters["offset"] = offset

        if collection == "actors":
            parameters["offset"] = offset

        if collection == "vulnerabilities":
            parameters["start_epoch"] = start.unix_format
            parameters["end_epoch"] = end.unix_format
            parameters["sort_order"] = "asc"

        if collection == "indicators":
            end = now
            if start.value < now.delta(days=-90).value:
                start = now.delta(days=-90)
            parameters["start_epoch"] = start.unix_format
            parameters["end_epoch"] = end.unix_format
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
            '''
            Save current state before exitting in order to provide
            the capability to start near the moment where it exitted.
            '''
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

    def run(self):
        for collection in self.mandiant_collections:

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                f"{collection.title()} {Timestamp.now().iso_format} - {Timestamp.now().iso_format}"
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