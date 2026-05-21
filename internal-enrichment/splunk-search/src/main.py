import traceback

from internal_enrichment_connector.config_loader import ConfigConnector
from internal_enrichment_connector.connector import SplunkSearchConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        config = ConfigConnector()
        helper = OpenCTIConnectorHelper(config=config.load, playbook_compatible=True)
        connector = SplunkSearchConnector(helper=helper, config=config)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
