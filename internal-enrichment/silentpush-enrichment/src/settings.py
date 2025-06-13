import os

import yaml
from pycti import get_config_variable

config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
config = (
    yaml.load(open(config_file_path), Loader=yaml.SafeLoader)
    if os.path.isfile(config_file_path)
    else {}
)
API_URI = get_config_variable(
    "SILENTPUSH_API_BASE_URL",
     ["silentpush", "api_base_url"],
    config,
    False,
    "https://app.silentpush.com/api/v1/",
)
API_VERIFY_CERT = get_config_variable(
    "API_VERIFY_CERT",
    ["silentpush", "CONNECTOR_SILENTPUSH_VERIFY_CERT"],
    config,
    False,
    True,
)
API_KEY = get_config_variable(
    "API_KEY", ["silentpush", "CONNECTOR_SILENTPUSH_API_KEY"], config
)
SILENTPUSH_SIGNATURE = "Silent Push"
ip_diversity_uri = (
    API_URI
    + "merge-api/explore/padns/lookup/ipdiversity/a/{domain}/?format=json&timeline=1&window=1"
)
enrich_uri = (
    API_URI + "merge-api/explore/enrich/{type}/{ioc}/?format=json&scan_data=1&explain=1"
)
