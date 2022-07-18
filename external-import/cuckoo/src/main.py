import os
import time
from datetime import datetime

import yaml
from cuckoo.cuckoo import cuckoo
from cuckoo.telemetry import openCTIInterface
from pycti import OpenCTIConnectorHelper, get_config_variable


class cuckooConnector:
    """Connector object"""

    def __init__(self):
        """Read in config variables"""

        config_file_path = os.path.dirname(os.path.abspath(__file__))
        config_file_path += "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.cuckoo_api_url = get_config_variable(
            "CUCKOO_API_URL", ["cuckoo", "api_url"], config
        )

        self.cuckoo_url = get_config_variable(
            "CUCKOO_BASE_URL", ["cuckoo", "base_url"], config
        )

        self.EnableNetTraffic = get_config_variable(
            "CUCKOO_ENABLE_NETWORK_TRAFFIC",
            ["cuckoo", "enable_network_traffic"],
            config,
            default=False,
        )
        self.EnableRegKeys = get_config_variable(
            "CUCKOO_ENABLE_REGISTRY_KEYS",
            ["cuckoo", "enable_registry_keys"],
            config,
            default=False,
        )

        self.verify_ssl = get_config_variable(
            "VERIFY_SSL", ["cuckoo", "verify_ssl"], config, default=True
        )

        self.interval = get_config_variable(
            "CUCKOO_INTERVAL", ["cuckoo", "interval"], config, True, 30
        )

        self.start_id = get_config_variable(
            "CUCKOO_START_TASK_ID", ["cuckoo", "start_task_id"], config, True, 0
        )

        self.report_score = get_config_variable(
            "CUCKOO_REPORT_SCORE", ["cuckoo", "report_score"], config, True, 0
        )

        self.create_indicators = get_config_variable(
            "CUCKOO_CREATE_INDICATORS", ["cuckoo", "create_indicators"], config
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        self.cuckoo_api: cuckoo = cuckoo(
            self.helper, self.cuckoo_api_url, self.verify_ssl
        )

    def get_interval(self):
        """Converts interval hours to seconds"""
        return int(self.interval) * 60

    @property
    def first_run(self):
        """Checks if connector has run before"""
        current_state = self.helper.get_state()
        return current_state is None or "last_run" not in current_state

    def run(self):
        """Run connector on a schedule"""
        while True:
            if self.first_run:
                state = self.helper.get_state()
                self.helper.log_info("Connector has never run")
                self.helper.log_info(str(state))

                # Get Last Cuckoo Task Pulled
                if not state:
                    current_task = 0
                else:
                    if "task" in state:
                        current_task = self.helper.get_state()["task"]
                    else:
                        current_task = 0

                # Check If starting Task > last task
                if self.start_id > current_task:
                    current_task = self.start_id
                    self.helper.set_state({"task": self.start_id})
            else:
                last_run = datetime.utcfromtimestamp(
                    self.helper.get_state()["last_run"]
                ).strftime("%Y-%m-%d %H:%M:%S")
                self.helper.log_info("Connector last run: " + last_run)

                # Get Last Cuckoo Task Pulled
                state = self.helper.get_state()
                self.helper.log_info(str(state))
                if not state:
                    current_task = 0
                    self.helper.log_info("Last Task ID (STATE): " + str(current_task))
                if "task" in state:
                    current_task = state["task"]
                    self.helper.log_info("Last Task ID (STATE): " + str(current_task))
                else:
                    current_task = 0

                # Check If starting Task > last task
                if self.start_id > current_task:
                    current_task = self.start_id
                    self.helper.set_state({"task": self.start_id})

            try:
                CuckooTasks = (
                    self.cuckoo_api.getCuckooTasks()
                )  # Pull List of tasks from the Cuckoo API
            except Exception as err:
                self.helper.log_error("Error connecting to Cuckoo API")
                self.helper.log_error(str(err))
                raise (err)

            for task in CuckooTasks:
                if not task["status"] == "reported":
                    continue  # If task Has not reported Skip
                if not task["completed_on"]:
                    continue  # If task Has not completed Skip

                try:
                    if task["id"] > current_task:
                        taskSummary = self.cuckoo_api.getTaskSummary(
                            task["id"]
                        )  # Pull Cuckoo Report and Searilize
                        if not taskSummary:
                            continue  # If no report continue
                        if not taskSummary.info:
                            continue  # If no report.info continue - we really need this :)

                        self.helper.log_info(f"Processing Task {taskSummary.info.id}")
                        # Process and submit cuckoo task as stix bundle
                        openCTIInterface(
                            taskSummary,
                            self.helper,
                            self.update_existing_data,
                            [],
                            self.create_indicators,
                            self.cuckoo_url,
                            self.EnableNetTraffic,
                            self.EnableRegKeys,
                            self.report_score,
                        )
                        # Update last task pulled
                        self.helper.set_state({"task": taskSummary.info.id})

                        self.helper.log_info(f"Synced task {task['id']}")
                except Exception as e:
                    self.helper.log_error(
                        f"An error Occured fetching task {task['id']}; {str(e)}"
                    )

            self.helper.log_info("Finished grabbing Cuckoo Reports")

            self.helper.log_info(
                f"Run Complete. Sleeping until next run in " f"{self.interval} Minutes"
            )

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                exit(0)

            time.sleep(self.get_interval())


if __name__ == "__main__":
    try:
        CONNECTOR = cuckooConnector()
        CONNECTOR.run()
    except Exception as e:
        raise e
