import yaml
import os
import requests
import json
import pycountry

from stix2 import Relationship, Identity, Bundle
from pycti import OpenCTIConnectorHelper


class IpInfoConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        self.helper = OpenCTIConnectorHelper(config)
        self.token = os.getenv('IPINFO_TOKEN') or config['ipinfo']['token']

    def _generate_stix_bundle(self, country, city, observable_id):
        # Generate stix bundle
        country_identity = Identity(
            name=country.name,
            identity_class='group',
            custom_properties={
                'x_opencti_identity_type': 'country',
                'x_opencti_alias': [country.official_name],
            }
        )
        city_identity = Identity(
            name=city,
            identity_class='group',
            custom_properties={
                'x_opencti_identity_type': 'city'
            }
        )
        city_to_country = Relationship(
            relationship_type='localization',
            source_ref=city_identity.id,
            target_ref=country_identity.id,
        )
        observable_to_city = Relationship(
            relationship_type='localization',
            source_ref=observable_id,
            target_ref=city_identity.id,
            custom_properties={
                'x_opencti_weight': self.helper.connect_confidence_level
            }
        )
        return Bundle(objects=[country_identity, city_identity,
                               city_to_country, observable_to_city]).serialize()

    def _process_message(self, data):
        entity_id = data['entity_id']
        observable = self.helper.api.get_stix_observable(entity_id)
        # Extract IP from entity data
        observable_id = observable['stix_id_key']
        observable_value = observable['observable_value']
        # Get the geo loc from the API
        api_url = 'https://ipinfo.io/' + observable_value + '?token=' + self.token
        response = requests.request("GET", api_url, headers={
            'accept': "application/json",
            'content-type': "application/json",
        })
        json_data = json.loads(response.text)
        country = pycountry.countries.get(alpha_2=json_data['country'])
        bundle = self._generate_stix_bundle(country, json_data['city'], observable_id)
        bundles_sent = self.helper.send_stix2_bundle(bundle)
        return ['Sent ' + str(len(bundles_sent)) + ' stix bundle(s) for worker import']

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == '__main__':
    ipInfoInstance = IpInfoConnector()
    ipInfoInstance.start()
