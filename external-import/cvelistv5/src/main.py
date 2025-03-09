import os
import time
import yaml
from threading import Thread
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
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        
        # OpenCTI config
        self.opencti_url = get_config_variable("OPENCTI_URL", ["opencti", "url"], config)
        self.opencti_token = get_config_variable("OPENCTI_TOKEN", ["opencti", "token"], config)
        
        # Connector config
        self.start_year = get_config_variable("CVE_HISTORY_START_YEAR", ["cvelistv5", "start_year"], config)
        self.update_interval = int(get_config_variable("CVE_INTERVAL", ["cvelistv5", "interval"], config)) * 60
        
        self.git_handler = GitHandler(
            repo_url='https://github.com/CVEProject/cvelistV5.git',
            local_path='main',
            branch='./'
        )
        
        self.cve_processor = CVEProcessor(self.helper, self.helper.api)

    def _process_updates(self):
        while True:
            try:
                self.git_handler.pull_updates()
                files_to_process = self.git_handler.get_updated_files(self.start_year)

                for file in files_to_process:
                    full_path = os.path.join(self.git_handler.local_path, file)
                    self.cve_processor.process_cve_file(full_path)

                self.helper.log_info(f"Processed {len(files_to_process)} files")
            except Exception as e:
                self.helper.log_error(f"Error processing updates: {str(e)}")
            time.sleep(self.update_interval)

    def start(self):
        self.helper.log_info("Starting CVE List V5 Connector")
        update_thread = Thread(target=self._process_updates)
        update_thread.start()
        self.helper.listen()

if __name__ == '__main__':
    CVEListV5Connector().start()
