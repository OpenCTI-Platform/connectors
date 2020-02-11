import yaml
import os
import json
import time

from pycti import OpenCTIConnectorHelper


class ExportFileStix:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader) if os.path.isfile(config_file_path) else {}
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, data):
        entity_id = data['entity_id']
        entity_type = data['entity_type']
        file_name = data['file_name']
        file_context = data['file_context']
        export_type = data['export_type']
        list_args = data['list_args']
        max_marking_definition = data['max_marking_definition']
        if entity_id is not None:
            self.helper.log_info(
                'Exporting: ' + entity_type + '/' + export_type + '(' + entity_id + ') to ' + file_name
            )
            bundle = self.helper.api.stix2.export_entity(entity_type, entity_id, export_type, max_marking_definition)
            json_bundle = json.dumps(bundle, indent=4)
            self.helper.log_info(
                'Uploading: ' + entity_type + '/' + export_type + '(' + entity_id + ') to ' + file_name
            )
            self.helper.api.stix_domain_entity.push_entity_export(entity_id, file_name, json_bundle)
            self.helper.log_info(
                'Export done: ' + entity_type + '/' + export_type + '(' + entity_id + ') to ' + file_name
            )
        else:
            self.helper.log_info('Exporting list: ' + entity_type + '/' + export_type + ' to ' + file_name)
            bundle = self.helper.api.stix2.export_list(
                entity_type.lower(),
                list_args['search'],
                list_args['filters'],
                list_args['orderBy'],
                list_args['orderMode'],
                max_marking_definition
            )
            json_bundle = json.dumps(bundle, indent=4)
            self.helper.log_info('Uploading: ' + entity_type + '/' + export_type + ' to ' + file_name)
            self.helper.api.stix_domain_entity.push_list_export(
                entity_type,
                file_name,
                json_bundle,
                file_context,
                json.dumps(list_args)
            )
            self.helper.log_info('Export done: ' + entity_type + '/' + export_type + ' to ' + file_name)
        return ['Export done']

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == '__main__':
    try:
        connectorExportFileStix = ExportFileStix()
        connectorExportFileStix.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
