import yaml
import os
import json

from pycti import OpenCTIConnectorHelper


class ExportFileStix:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, data):
        entity_id = data['entity_id']
        file_name = data['file_name']
        entity_type = data['entity_type']
        export_type = data['export_type']
        self.helper.log_info('Exporting: ' + entity_type + '/' + export_type + '(' + entity_id + ') to ' + file_name)
        bundle = self.helper.api.stix2_export_entity(entity_type, entity_id, export_type)
        json_bundle = json.dumps(bundle, indent=4)
        self.helper.log_info('Uploading: ' + entity_type + '/' + export_type + '(' + entity_id + ') to ' + file_name)
        self.helper.api.push_stix_domain_entity_export(entity_id, file_name, json_bundle)
        self.helper.log_info('Export done: ' + entity_type + '/' + export_type + '(' + entity_id + ') to ' + file_name)
        return ['Export done']

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == '__main__':
    connectorExportFileStix = ExportFileStix()
    connectorExportFileStix.start()
