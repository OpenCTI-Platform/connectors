import yaml
import os
import requests
import json

from connector.opencti_connector_helper import OpenCTIConnectorHelper


class EnrichIpAddrGeo:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, job_id, job_answer, data):
        now = self.helper.date_now()  # Generate the current date
        entity_id = data['entity_id']
        observable = self.helper.api.get_stix_observable(entity_id)
        # Extract IP from entity data
        observable_id = observable['id']
        observable_value = observable['observable_value']
        # Get the geo loc from the API
        api_url = 'http://ip-api.com/json/' + observable_value
        response = requests.request("GET", api_url, headers={
            'accept': "application/json",
            'content-type': "application/json"
        })
        json_data = json.loads(response.text)
        observable_city = json_data['city']

        # Lookup the existing observable localization
        # - If localized relation already exists, update it
        existing_relations = observable['stixRelations']
        if len(existing_relations['edges']) > 0:
            nodes = list(map(lambda item: item['node'], existing_relations['edges']))
            existing_city_relations = list(
                filter(lambda node: node['relationship_type'] == 'localization'
                                    and node['to']['name'].casefold() == observable_city.casefold(), nodes)
            )
            if len(existing_city_relations) == 1:
                city_relation = existing_city_relations[0]
                self.helper.api.update_stix_relation_field(city_relation['id'], 'last_seen', now)
                job_answer.add_message('Update localized relation last_seen to '
                                       + observable_city + ' (' + observable_id + ')')
                return
            elif len(existing_city_relations) > 1:
                raise Exception('Multiple localized relations exists for ' + observable_id)

        # - If localized not exists, create it
        # -- Get the internal_id of the targeted city in openCTI
        opencti_city = self.helper.api.get_stix_domain_entity_by_name(observable_city)
        if opencti_city is None:
            opencti_city = self.helper.api.city.create_city(observable_city)
        # Create the relation
        city_id = opencti_city['id']
        relation = self.helper.api.create_relation(observable_id, 'localized', city_id, 'location', 'localization',
                                                   'Created by ' + self.helper.connector.name, now, now)
        job_answer.add_message('Create localized relation ' + relation['id'] + ' to '
                               + observable_city + ' for ' + observable_id)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == '__main__':
    enrich_ip_addr_geo = EnrichIpAddrGeo()
    enrich_ip_addr_geo.start()
