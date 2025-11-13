import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from threatmatch.config import ConnectorSettings

# Ensure local config is not loaded
ConnectorSettings.model_config["yaml_file"] = ""
