import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from gpt_enrichment.core import GptEnrichmentConnector 



if __name__ == "__main__":
    try:
        connector = GptEnrichmentConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
