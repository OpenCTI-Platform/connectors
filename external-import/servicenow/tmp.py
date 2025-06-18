import json

from src.connector.models import ConfigLoader

# Example
# dict = {"teeest":"teeest", "add": 1}
# print(json.dumps(dict, indent=2))

get_connector_config = ConfigLoader
connector_json_schema = get_connector_config.model_json_schema()
format_connector_schema = json.dumps(connector_json_schema, indent=2)

print(format_connector_schema)
