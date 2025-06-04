# Main Exectuion file
import os
import datetime
import json
import yaml
from git_handler import GitHandler
from cve_processor import CVEProcessor
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
)


class CVEListV5Connector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # OpenCTI config
        self.opencti_url = get_config_variable("OPENCTI_URL", ["opencti", "url"], config)
        self.opencti_token = get_config_variable("OPENCTI_TOKEN", ["opencti", "token"], config)

        # Connector config
        self.start_year = int(get_config_variable("CVE_HISTORY_START_YEAR", ["cvelistv5", "start_year"], config))
        #self.update_interval = int(get_config_variable("CVE_INTERVAL", ["cvelistv5", "interval"], config)) * 60
        self.duration_period = get_config_variable("CONNECTOR_DURATION_PERIOD", ["connector", "duration_period"], config)

        self._log_message("Initiliazing: Cloning CVEProject/cvelistV5...")
        self.git_handler = GitHandler(
            repo_url='https://github.com/CVEProject/cvelistV5.git',
            local_path='/opt/cvelistV5'
        )
        self._log_message("Git repo clone complete.")

        state = self.helper.get_state()
        if 'last_update' in state:
            self.git_handler.last_run_time = state['last_update']

        self.cve_processor = CVEProcessor(self.helper, self.helper.api)


    def _log_message(self, message: str):
        self.helper.log_info(message)
        state = self.helper.get_state()
        self.helper.log_debug(f"Original state: {json.dumps(state)}")
        if not state:
            state = {}
        state['message'] = message
        self.helper.set_state(state)


    def _process_updates(self):
        #while True:
        try:

            friendly_name = "CVEListV5 run @ " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
            self.git_handler.pull_updates()
            files_to_process = self.git_handler.get_updated_files(self.start_year)

            for file in files_to_process:
                self.helper.log_debug(f"Processing the file at {file}")
                self.cve_processor.process_cve_file(file, work_id)

            message = f"Processed {len(files_to_process)} files"
            self.helper.log_info(message)
            self.helper.set_state(
                {"last_update": str(self.git_handler.last_run_time), 'message': message}
            )
            self.helper.api.work.to_processed(work_id, message)
        except Exception as e:
            message = f"Error processing updates: {str(e)}"
            self.helper.log_error(message)
            self._log_message(message)

    def start(self):
        self.helper.log_info("Starting CVE List V5 Connector")
        self.helper.schedule_iso(
                message_callback=self._process_updates, 
                duration_period=self.duration_period
        )

if __name__ == '__main__':
    CVEListV5Connector().start()
