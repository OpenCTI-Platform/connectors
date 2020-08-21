import yaml
import os
import requests
import json
import pycountry

from stix2 import Relationship, Location, Bundle
from pycti import OpenCTIConnectorHelper, get_config_variable


class IpInfoConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.token = get_config_variable("IPINFO_TOKEN", ["ipinfo", "token"], config)
        self.max_tlp = get_config_variable(
            "IPINFO_MAX_TLP", ["ipinfo", "max_tlp"], config
        )

    def _generate_stix_bundle(self, country, city, observable_id):
        # Generate stix bundle
        country_identity = Location(
            name=country.name,
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_aliases": [
                    country.official_name
                    if hasattr(country, "official_name")
                    else country.name
                ],
            },
        )
        city_identity = Location(
            name=city, custom_properties={"x_opencti_location_type": "city"},
        )
        city_to_country = Relationship(
            relationship_type="located-at",
            source_ref=city_identity.id,
            target_ref=country_identity.id,
        )
        observable_to_city = Relationship(
            relationship_type="located-at",
            source_ref=observable_id,
            target_ref=city_identity.id,
            confidence=self.helper.connect_confidence_level,
        )
        return Bundle(
            objects=[
                country_identity,
                city_identity,
                city_to_country,
                observable_to_city,
            ]
        ).serialize()

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_observable.read(id=entity_id)
        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable["markingDefinitions"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        # Extract IP from entity data
        observable_id = observable["stix_id_key"]
        observable_value = observable["observable_value"]
        # Get the geo loc from the API
        api_url = "https://ipinfo.io/" + observable_value + "?token=" + self.token
        response = requests.request(
            "GET",
            api_url,
            headers={"accept": "application/json", "content-type": "application/json"},
        )
        json_data = json.loads(response.text)
        country = pycountry.countries.get(alpha_2=json_data["country"])
        if country is None:
            raise ValueError(
                "IpInfo was not able to find a country for this IP address"
            )
        bundle = self._generate_stix_bundle(country, json_data["city"], observable_id)
        bundles_sent = self.helper.send_stix2_bundle(bundle)
        return ["Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"]

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    ipInfoInstance = IpInfoConnector()
    ipInfoInstance.start()
