import logging
import time

from feedly.opencti_connector.runner import FeedlyRunner
from models import ConfigLoader
from pycti import OpenCTIConnectorHelper


def load_helper() -> tuple[OpenCTIConnectorHelper, ConfigLoader]:
    """Load configuration and create OpenCTI helper."""
    config = ConfigLoader()
    for _ in range(10):
        try:
            helper = OpenCTIConnectorHelper(config.model_dump_pycti())
            return helper, config
        except ValueError as e:
            if "OpenCTI API is not reachable" not in e.args[0]:
                raise e
            logging.warning("Failed to connect to OpenCTI API. Retying in 30 seconds.")
            time.sleep(30)


if __name__ == "__main__":
    _helper, _config = load_helper()
    _runner = FeedlyRunner(_helper, _config)
    if _helper.connect_run_and_terminate:
        _runner.run_once()
        _helper.force_ping()
    else:
        _runner.run()
