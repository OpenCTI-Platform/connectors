import os
import yaml
import time
from pycti import OpenCTIConnectorHelper, get_config_variable


class TemplateConnector:
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
    # https://www.notion.so/luatix/Connector-Development-06b2690697404b5ebc6e3556a1385940
    ####


if __name__ == "__main__":
    try:
        connector = TemplateConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
