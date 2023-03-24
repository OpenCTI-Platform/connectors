import datetime
import importlib
import sys
import time
import traceback

from dateutil.parser import parse
from mandiant.api import MandiantAPI
from pycti import OpenCTIConnectorHelper, get_config_variable

MANDIANT_API_URL = "https://api.intelligence.mandiant.com"
INITIAL_STATE = {
    "actor": 0,
    "malware": 0,
    "vulnerability": 0,
    "indicator": 0,
    "report": 0,
}


class Mandiant:
    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA", [""]
        )
        self.mandiant_api_url = get_config_variable(
            "MANDIANT_API_URL", [""], default=MANDIANT_API_URL
        )
        self.mandiant_api_v4_key_id = get_config_variable(
            "MANDIANT_API_V4_KEY_ID", [""]
        )
        self.mandiant_api_v4_key_secret = get_config_variable(
            "MANDIANT_API_V4_KEY_SECRET", [""]
        )
        self.mandiant_collections = get_config_variable(
            "MANDIANT_COLLECTIONS",
            [""],
            default="actor,malware,indicator,vulnerability,report",
        ).split(",")
        self.mandiant_import_start_date = get_config_variable(
            "MANDIANT_IMPORT_START_DATE", [""], default="2023-01-01"
        )
        self.mandiant_interval = get_config_variable(
            "MANDIANT_INTERVAL", [""], isNumber=True, default=1
        )
        self.mandiant_report_types_ignored = get_config_variable(
            "MANDIANT_REPORT_TYPES_IGNORED", [""], default="News Analysis"
        ).split(",")
        self.mandiant_indicator_minimum_score = get_config_variable(
            "MANDIANT_INDICATOR_MINIMUM_SCORE", [""], default=80
        )

        self.mandiant_interval = int(self.mandiant_interval) * 60
        self.mandiant_import_start_date = int(
            parse(self.mandiant_import_start_date).timestamp()
        )

        self.identity = self.helper.api.identity.create(
            id="identity--28dc7d92-5db5-57d8-9c82-e151d743bb93",
            type="Organization",
            name="Mandiant, Inc",
        )

        self.api = MandiantAPI(
            self.mandiant_api_v4_key_id, self.mandiant_api_v4_key_secret
        )
        self.cache = {}

    def run(self):
        while True:
            try:
                self.helper.log_info("Synchronizing with Mandiant API...")

                timestamp = int(time.time())
                now = datetime.datetime.utcfromtimestamp(timestamp)
                friendly_name = "Mandiant run @ " + now.strftime("%Y-%m-%d %H:%M:%S")

                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                current_state = self.helper.get_state()

                if not current_state:
                    self.helper.set_state(INITIAL_STATE)
                    current_state = self.helper.get_state()

                for collection in current_state.keys():
                    if collection not in self.mandiant_collections:
                        continue

                    module = importlib.import_module(
                        f".{collection}", package=__package__
                    )
                    self.helper.log_info(
                        f"Get {collection} after position {current_state[collection]}"
                    )
                    new_state = module.process(self, work_id, current_state)
                    self.helper.log_info("Setting new state " + str(new_state))
                    self.helper.set_state(new_state)

                message = "End of synchronization"

                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)

                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    sys.exit(0)

                time.sleep(self.mandiant_interval)

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)

            except Exception as e:
                self.helper.log_error(str(e))
                self.helper.log_error(traceback.format_exc())

                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    sys.exit(0)

                time.sleep(60)
