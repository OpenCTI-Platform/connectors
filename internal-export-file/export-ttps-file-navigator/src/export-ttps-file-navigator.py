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

        supported_entity_types = ['Malware', 'Tool', 'Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual',
                                  'Report']
        if data['export_type'] != 'simple':
            raise ValueError(
                'This connector currently only handles direct export (single entity and no list)'
            )
        if data['entity_type'] not in supported_entity_types:
            raise ValueError(
                f'This connector only export in MITRE Navigator format techniques '
                f'associated to the following entity types: {supported_entity_types})'
            )

        self.helper.log_info("je suis la")
        self.helper.log_info(data)

        # Get entity data
        entity_id = data["entity_id"]
        entity_name = data["entity_name"]
        entity_type = data['entity_type']

        # file_name = data['file_name']
        file_name = "export-techniques-layer-" + entity_type + "-" + entity_name + ".json"
        self._process_entity_export(entity_id, entity_name, file_name)
        return "Export done"

    def _process_entity_export(self, entity_id, entity_name, file_name):
        self.helper.log_info("je suis dans _process_entity_export")
        self.helper.log_info(entity_id)

        associated_ttps = []
        # Get the relations from the main entity to attack pattern
        stix_relations = self.helper.api_impersonate.stix_core_relationship.list(
            fromId=entity_id, toTypes=["Attack-Pattern"]
        )
        self.helper.log_info(stix_relations)
        for relation in stix_relations:
            attack_pattern = self.helper.api_impersonate.attack_pattern.read(id=relation['to']['id'])
            self.helper.log_info(attack_pattern['x_mitre_id'])
            associated_ttps.append(attack_pattern)

        # self.helper.log_info(associated_ttps)
        # Upload the output pdf
        # self.helper.log_info(f"Uploading: {file_name}")
        # self.helper.api.stix_domain_object.push_entity_export(
        #    report_id, file_name, pdf_contents, "application/pdf"
        # )
        layer = self.build_layer(entity_name, associated_ttps)
        self.helper.api.stix_domain_object.push_entity_export(
            entity_id=entity_id,
            file_name=file_name,
            data=json.dumps(layer).encode('utf-8'),
            mime_type="application/json"
        )

    @staticmethod
    def build_layer(entity_name, ttps):
        layer = {
            "name": entity_name,
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": "",
            "sorting": 0,
            "techniques": []
        }
        for ttp in ttps:
            for kill_chain in ttp['killChainPhases']:
                technique = {
                    "techniqueID": ttp['x_mitre_id'],
                    "tactic": kill_chain['phase_name'].lower().replace(" ", "-"),
                    "color": "#e60d0d",
                    "comment": "",
                    "enabled": True,
                    "metadata":
                        [],
                    "links":
                        [],
                    "showSubtechniques": False
                }
                layer['techniques'].append(technique)
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
