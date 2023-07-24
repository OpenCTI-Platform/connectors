import logging
import os
import time

import yaml
from feedly.opencti_connector.runner import FeedlyRunner
from pycti import OpenCTIConnectorHelper


def load_helper() -> OpenCTIConnectorHelper:
    config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
    config = yaml.load(open(config_file_path), Loader=yaml.FullLoader) if os.path.isfile(config_file_path) else {}
    for _ in range(10):
        try:
            return OpenCTIConnectorHelper(config)
        except ValueError as e:
            if "OpenCTI API is not reachable" not in e.args[0]:
                raise e
            logging.warning("Failed to connect to OpenCTI API. Retying in 30 seconds.")
            time.sleep(30)


if __name__ == "__main__":
    _helper = load_helper()
    _runner = FeedlyRunner(_helper)
    if _helper.connect_run_and_terminate:
        _runner.run_once()
    else:
        _runner.run()
