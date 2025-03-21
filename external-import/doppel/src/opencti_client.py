from pycti import OpenCTIConnectorHelper
import yaml

# Load configuration
with open("config/config.yaml", "r") as f:
    config = yaml.safe_load(f)


# Ensure OpenCTI config is correctly structured
helper_config = {
    "opencti": {
        "url": config["opencti"]["url"],
        "token": config["opencti"]["api_key"],
    }
}

# Initialize OpenCTIConnectorHelper
helper = OpenCTIConnectorHelper(helper_config)
