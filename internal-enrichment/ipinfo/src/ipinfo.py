import os

import pycountry
import requests
import stix2
import yaml
from pycti import (
    Location,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


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

    def _generate_stix_bundle(self, country, city, loc, observable_id):
        # Generate stix bundle
        country_location = stix2.Location(
            id=Location.generate_id(country.name, "Country"),
            name=country.name,
            country=country.official_name
            if hasattr(country, "official_name")
            else country.name,
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_aliases": [
                    country.official_name
                    if hasattr(country, "official_name")
                    else country.name
                ],
            },
        )
        loc_split = loc.split(",")
        city_location = stix2.Location(
            id=Location.generate_id(city, "City"),
            name=city,
            country=country.official_name
            if hasattr(country, "official_name")
            else country.name,
            latitude=loc_split[0],
            longitude=loc_split[1],
            custom_properties={"x_opencti_location_type": "City"},
        )
        city_to_country = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "located-at", city_location.id, country_location.id
            ),
            relationship_type="located-at",
            source_ref=city_location.id,
            target_ref=country_location.id,
        )
        observable_to_city = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "located-at", observable_id, city_location.id
            ),
            relationship_type="located-at",
            source_ref=observable_id,
            target_ref=city_location.id,
            confidence=self.helper.connect_confidence_level,
        )
        return stix2.Bundle(
            objects=[
                country_location,
                city_location,
                city_to_country,
                observable_to_city,
            ],
            allow_custom=True,
        ).serialize()

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, check the group of the connector user)"
            )

        # Extract TLP
        tlp = "TLP:CLEAR"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        # Extract IP from entity data
        observable_id = observable["standard_id"]
        observable_value = observable["value"]
        # Get the geo loc from the API
        api_url = "https://ipinfo.io/" + observable_value + "/json/?token=" + self.token
        response = requests.request(
            "GET",
            api_url,
            headers={"accept": "application/json", "content-type": "application/json"},
        )
        json_data = response.json()
        if "status" in json_data and json_data["status"] == 429:
            raise ValueError("IpInfo Rate limit exceeded")
        if "country" not in json_data:
            raise ValueError("Country not found, an error occurred")
        country = pycountry.countries.get(alpha_2=json_data["country"])
        if country is None:
            raise ValueError(
                "IpInfo was not able to find a country for this IP address"
            )
        bundle = self._generate_stix_bundle(
            country, json_data["city"], json_data["loc"], observable_id
        )
        bundles_sent = self.helper.send_stix2_bundle(bundle)
        return "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    ipInfoInstance = IpInfoConnector()
    ipInfoInstance.start()
