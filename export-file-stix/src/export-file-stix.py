# coding: utf-8

import yaml
import os
import json

from connector.opencti_connector_helper import OpenCTIConnectorHelper


class StixExporter:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, job_id, job_answer, data):
        entity_id = data['entity_id']
        file_name = data['file_name']
        entity_type = data['entity_type']
        export_type = data['export_type']
        self.helper.log_info('Exporting: ' + entity_type + '/' + export_type + '(' + entity_id + ') to ' + file_name)
        bundle = self.helper.api.stix2_export_entity(entity_type, entity_id, export_type)
        json_bundle = json.dumps(bundle, indent=4)
        self.helper.log_info('Uploading: ' + entity_type + '/' + export_type + '(' + entity_id + ') to ' + file_name)
        self.helper.api.push_stix_domain_entity_export(job_id, entity_id, file_name, json_bundle)
        msg = 'Export done: ' + entity_type + '/' + export_type + '(' + entity_id + ') to ' + file_name
        self.helper.log_info(msg)
        job_answer.add_message(msg)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == '__main__':
    stix_exporter = StixExporter()
    stix_exporter.start()
