import os
import time
from threading import Thread
from pycti import OpenCTIConnectorHelper
from .git_handler import GitHandler
from .cve_processor import CVEProcessor

class CVEListV5Connector:
    def __init__(self):
        config = self.helper.config
        self.helper = OpenCTIConnectorHelper(config)
        self.git_handler = GitHandler(
            config['cvelistv5']['url'],
            config['cvelistv5']['local_path'],
            config['cvelistv5']['branch']
        )
        self.cve_processor = CVEProcessor(self.helper, self.helper.api)
        self.start_year = int(config['cvelistv5']['start_year'])
        self.update_interval = int(config['cvelistv5'].get('interval', 10)) * 60 # Multiplies with 60 seconds to Default to 10 minutes

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
