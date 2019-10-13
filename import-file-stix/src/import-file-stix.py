import os
import yaml

from connector.opencti_connector_helper import OpenCTIConnectorHelper


class StixImporter:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, job_id, job_answer, data):
        file_path = data['file_path']
        file_uri = self.helper.opencti_url + file_path
        self.helper.log_info('Importing the file ' + file_uri)
        imported_elements = self.helper.api.stix2_import_bundle_from_uri(file_uri, True)
        if imported_elements is None:
            job_answer.add_message('Nothing imported')
        else:
            for imported_element in imported_elements:
                job_answer.add_message(imported_element['type'] + ' - ' + imported_element['id'])

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == '__main__':
    stix_imported = StixImporter()
    stix_imported.start()
