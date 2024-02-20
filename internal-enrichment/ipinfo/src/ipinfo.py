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
        self.helper = OpenCTIConnectorHelper(config, True)
        self.token = get_config_variable("IPINFO_TOKEN", ["ipinfo", "token"], config)
        self.max_tlp = get_config_variable(
            "IPINFO_MAX_TLP", ["ipinfo", "max_tlp"], config
        )

    def _generate_stix_bundle(self, stix_objects, stix_entity, country, city, loc):
        # Generate stix bundle
        country_location = stix2.Location(
            id=Location.generate_id(country.name, "Country"),
            name=country.name,
            country=(
                country.official_name
                if hasattr(country, "official_name")
                else country.name
            ),
            confidence=self.helper.connect_confidence_level,
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_aliases": [
                    (
                        country.official_name
                        if hasattr(country, "official_name")
                        else country.name
                    )
                ],
            },
        )
        stix_objects.append(country_location)
        loc_split = loc.split(",")
        city_location = stix2.Location(
            id=Location.generate_id(city, "City"),
            name=city,
            country=(
                country.official_name
                if hasattr(country, "official_name")
                else country.name
            ),
            latitude=loc_split[0],
            longitude=loc_split[1],
            confidence=self.helper.connect_confidence_level,
            custom_properties={"x_opencti_location_type": "City"},
        )
        stix_objects.append(city_location)
        city_to_country = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "located-at", city_location.id, country_location.id
            ),
            relationship_type="located-at",
            source_ref=city_location.id,
            target_ref=country_location.id,
            confidence=self.helper.connect_confidence_level,
        )
        stix_objects.append(city_to_country)
        observable_to_city = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "located-at", stix_entity["id"], city_location.id
            ),
            relationship_type="located-at",
            source_ref=stix_entity["id"],
            target_ref=city_location.id,
            confidence=self.helper.connect_confidence_level,
        )
        stix_objects.append(observable_to_city)
        return self.helper.stix2_create_bundle(stix_objects)

    def _process_message(self, data):
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["opencti_entity"]

        # Extract TLP
        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        # Get the geo loc from the API
        api_url = (
            "https://ipinfo.io/" + stix_entity["value"] + "/json/?token=" + self.token
        )
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
            stix_objects, stix_entity, country, json_data["city"], json_data["loc"]
        )
        bundles_sent = self.helper.send_stix2_bundle(bundle)
        return "Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import"

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message, auto_resolution=True)


if __name__ == "__main__":
    ipInfoInstance = IpInfoConnector()
    ipInfoInstance.start()
