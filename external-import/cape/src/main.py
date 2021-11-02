import os, time, yaml
from datetime import datetime
from sentry_sdk.api import capture_exception
from pycti import OpenCTIConnectorHelper, get_config_variable
from cape.cape import cuckoo, cuckooReport
from cape.telemetry import openCTIInterface

import sentry_sdk

sentry_sdk.init(
    "https://eff449c4ca3e449c86df8de099352113@sentry.infosec-ops.com:8443/3",
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    # We recommend adjusting this value in production.
    traces_sample_rate=1.0,
)


class capeConnector:
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

        self.cape_api_url = get_config_variable(
            "CAPE_API_URL", ["cape", "api_url"], config
        )

        self.cape_url = get_config_variable(
            "CAPE_BASE_URL", ["cape", "base_url"], config
        )

        self.EnableNetTraffic = get_config_variable(
            "CAPE_ENABLE_NETWORK_TRAFFIC",
            ["cape", "enable_network_traffic"],
            config,
            default=False,
        )
        self.EnableRegKeys = get_config_variable(
            "CAPE_ENABLE_REGISTRY_KEYS",
            ["cape", "enable_registry_keys"],
            config,
            default=False,
        )

        self.verify_ssl = get_config_variable(
            "VERIFY_SSL", ["cape", "verify_ssl"], config, default=True
        )

        self.interval = get_config_variable(
            "CAPE_INTERVAL", ["cape", "interval"], config, True, 30
        )

        self.start_id = get_config_variable(
            "CAPE_START_TASK_ID", ["cape", "start_task_id"], config, True, 0
        )

        self.report_score = get_config_variable(
            "CAPE_REPORT_SCORE", ["cape", "report_score"], config, True, 0
        )

        self.create_indicators = get_config_variable(
            "CAPE_CREATE_INDICATORS", ["cape", "create_indicators"], config
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        self.cape_api: cuckoo = cuckoo(self.helper, self.cape_api_url, self.verify_ssl)

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

                # Get Last Cape Task Pulled
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

                # Get Last Cape Task Pulled
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
                CapeTasks = (
                    self.cape_api.getCuckooTasks()
                )  # Pull List of tasks from the Cape API
            except Exception as err:
                self.helper.log_error("Error connecting to Cape API")
                self.helper.log_error(str(err))
                raise (err)

            for task in reversed(CapeTasks):
                if not task["status"] == "reported":
                    continue  # If task Has not reported Skip
                if not task["completed_on"]:
                    continue  # If task Has not completed Skip

                try:
                    if task["id"] > current_task:
                        taskSummary = cuckooReport(
                            self.cape_api.getTaskReport(task["id"])
                        )  # Pull Cape Report and Searilize
                        if not taskSummary:
                            continue  # If no report continue
                        if not taskSummary.info:
                            continue  # If no report.info continue - we really need this :)

                        self.helper.log_info(f"Processing Task {taskSummary.info.id}")
                        # Process and submit cape task as stix bundle
                        openCTIInterface(
                            taskSummary,
                            self.helper,
                            self.update_existing_data,
                            [],
                            self.create_indicators,
                            self.cape_url,
                            self.EnableNetTraffic,
                            self.EnableRegKeys,
                            self.report_score,
                        )
                        # Update last task pulled
                        self.helper.set_state({"task": taskSummary.info.id})

                        self.helper.log_info(f"Synced task {task['id']}")
                except Exception as e:
                    capture_exception(e)
                    self.helper.log_error(
                        f"An error Occured fetching task {task['id']}; {str(e)}"
                    )

            self.helper.log_info("Finished grabbing Cape Reports")

            self.helper.log_info(
                f"Run Complete. Sleeping until next run in " f"{self.interval} Minutes"
            )

            time.sleep(self.get_interval())


if __name__ == "__main__":
    try:
        CONNECTOR = capeConnector()
        CONNECTOR.run()
    except Exception as e:
        raise e
