import json
import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper


class ExportTTPsFileNavigator:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        print(config_file_path)
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, data):
        if "entity_type" not in data or "entity_id" not in data:
            raise ValueError(
                "This Connector currently only handles direct export (single entity and not list)"
            )
        file_name = data["file_name"]
        export_scope = data["export_scope"]  # query or selection or single
        export_type = data["export_type"]  # Simple or Full
        entity_name = data["entity_name"]
        entity_type = data["entity_type"]

        # handle single export
        if export_scope == "single":
            entity_id = data["entity_id"]
            self.helper.log_info(
                "Exporting: " + entity_id + "(" + export_type + ") to " + file_name
            )
            layer = self._process_entity_export(entity_id, entity_name)
            json_bundle = json.dumps(layer, indent=4)
            self.helper.log_info(
                "Uploading: " + entity_id + "(" + export_type + ") to " + file_name
            )
            self.helper.api.stix_domain_object.push_entity_export(
                entity_id=entity_id, file_name=file_name, data=json_bundle
            )
            self.helper.log_info(
                "Export done: "
                + entity_type
                + "/"
                + export_type
                + "("
                + entity_id
                + ") to "
                + file_name
            )

    def _process_entity_export(self, entity_id, entity_name):
        related_ttps = []
        # Get the relations from the main entity to attack pattern
        stix_relations = self.helper.api_impersonate.stix_core_relationship.list(
            fromId=entity_id, toTypes=["Attack-Pattern"]
        )
        for relation in stix_relations:
            attack_pattern = self.helper.api_impersonate.attack_pattern.read(
                id=relation["to"]["id"]
            )
            related_ttps.append(attack_pattern)
        return self.build_layer(entity_name, related_ttps)

    @staticmethod
    def build_layer(entity_name, ttps):
        layer = {
            "name": entity_name,
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "",
            "sorting": 0,
            "techniques": [],
        }
        for ttp in ttps:
            technique = {
                "techniqueID": ttp["x_mitre_id"],
                "color": "#e60d0d",
                "comment": "",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False,
            }
            layer["techniques"].append(technique)
        return layer

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connectorExportTTPsFileNavigator = ExportTTPsFileNavigator()
        connectorExportTTPsFileNavigator.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
