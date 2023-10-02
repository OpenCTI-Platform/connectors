import os

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class Cluster25:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.cve_interval = get_config_variable(
            "TEMPLATE_ATTRIBUTE", ["template", "attribute"], config, True
        )

    ####
    # TODO add your code according to your connector type
    # For details: see
    # https://docs.opencti.io/latest/development/connectors/
    ####