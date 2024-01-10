import os
import sys
import time
from datetime import datetime
import api
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class Citalid:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.citalid_customer_sub_domain_url = get_config_variable(
            "CITALID_CUSTOMER_SUB_DOMAIN_URL", ["citalid", "customer_sub_domain_url"], config,
        )
        self.citalid_user = get_config_variable(
            "CITALID_USER", ["citalid", "user"], config,
        )
        self.citalid_password = get_config_variable(
            "CITALID_PASSWORD", ["citalid", "password"], config,
        )
        self.citalid_interval = get_config_variable(
            "CITALID_INTERVAL", ["citalid", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        # Create the Citalid identity
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Citalid",
            description="Citalid is a french software vendor specialized in cyber risk management.",
        )

    def get_interval(self):
        return int(self.citalid_interval) * 60 * 60

    def process_data(self):
        try:
            # Get the current timestamp and check
            current_state = self.helper.get_state()
            if current_state is None or "last_loaded_bundle_timestamp" not in current_state:
                last_loaded_bundle_timestamp = None
            else:
                last_loaded_bundle_timestamp = current_state["last_loaded_bundle_timestamp"]

            now = datetime.now()
            friendly_name = "Citalid run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.log_info('Connecting to customer sub domain ...')
            api_client = api.Client(self.citalid_customer_sub_domain_url)
            api_client.login(self.citalid_user, self.citalid_password)

            self.helper.log_info('Fetching last bundle version info ...')
            last_version_metadata = api_client.get_last_version()
            file_timestamp = last_version_metadata["timestamp"]
            raw_file_date = last_version_metadata["date"]
            file_date = datetime.strptime(raw_file_date, '%Y-%m-%d').strftime('%Y-%m-%d %H:%M:%S')

            if last_loaded_bundle_timestamp is None or file_timestamp > last_loaded_bundle_timestamp:
                self.helper.log_info('Processing file "' + file_date + '"')
                bundle = api_client.get_latest_bundle()
                self.send_bundle(work_id, bundle)
                last_loaded_bundle_timestamp = file_timestamp
                # Store the current timestamp as a last run
                message = "Bundle successfully loaded, storing last_loaded_bundle_timestamp as " + str(
                    last_loaded_bundle_timestamp
                )
                self.helper.log_info(message)
                self.helper.set_state({"last_loaded_bundle_timestamp": last_loaded_bundle_timestamp})

            message = "Connector successfully run"
            self.helper.log_info(message)
            self.helper.api.work.to_processed(work_id, message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def send_bundle(self, work_id: str, serialized_bundle: str) -> None:
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")

    def run(self):
        self.helper.log_info("Fetching Citalid datasets...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.get_interval())


if __name__ == "__main__":
    try:
        citalidConnector = Citalid()
        citalidConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
