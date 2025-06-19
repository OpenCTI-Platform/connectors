import json
import os

from src.connector.models import ConfigLoader
from pydantic.json_schema import GenerateJsonSchema
# Example
# dict = {"teeest":"teeest", "add": 1}
# print(json.dumps(dict, indent=2))

def load_connector_infos(filename: str) -> dict:
    """
    Utility function to load a json file to a dict
    :param filename: Filename in string
    :return:
    """
    filepath = os.path.join(os.path.dirname(__file__), "__infos__", filename)
    with open(filepath, encoding="utf-8") as json_file:
        return json.load(json_file)

connector_infos = load_connector_infos("connector_infos.json")

class ConnectorCustomGenerator(GenerateJsonSchema):
    def generate(self, schema, mode='validation'):
        json_schema = super().generate(schema, mode=mode)
        json_schema['$schema'] = self.schema_dialect
        json_schema['$id'] = connector_infos["id"]
        json_schema['title'] = connector_infos["title"]
        json_schema['description'] = connector_infos["description"]
        json_schema['short_description'] = connector_infos["short_description"]
        json_schema['manager_supported'] = connector_infos["manager_supported"]
        json_schema['container_version'] = connector_infos["container_version"]
        json_schema['container_image'] = connector_infos["container_image"]
        json_schema['container_type'] = connector_infos["container_type"]
        json_schema['verified'] = connector_infos["verified"]
        json_schema['last_verified_date'] = connector_infos["last_verified_date"]
        json_schema['playbook_supported'] = connector_infos["playbook_supported"]
        json_schema['images'] = connector_infos["images"]
        json_schema['trial_link'] = connector_infos["trial_link"]
        json_schema['subscription_link'] = connector_infos["subscription_link"]
        json_schema['source_code'] = connector_infos["source_code"]

        return json_schema

get_connector_config = ConfigLoader
connector_json_schema = get_connector_config.model_json_schema(schema_generator=ConnectorCustomGenerator)

format_connector_schema = json.dumps(connector_json_schema, indent=2)
print(format_connector_schema)
