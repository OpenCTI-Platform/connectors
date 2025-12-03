import re
import traceback
from typing import Dict

import pycountry
import requests
import stix2
from pycti import Location, OpenCTIConnectorHelper, StixCoreRelationship
from src import ConfigLoader


class IpInfoConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(
            config=self.config.model_dump_pycti(), playbook_compatible=True
        )
        self.token = self.config.ipinfo.token
        self.max_tlp = self.config.ipinfo.max_tlp
        self.use_asn_name = self.config.ipinfo.use_asn_name

    def _generate_stix_bundle(
        self, stix_objects, stix_entity, country, city, loc, asn, privacy
    ):
        # Generate stix bundle
        if privacy:
            labels = []
            if privacy["vpn"]:
                labels.append("vpn")
            if privacy["proxy"]:
                labels.append("proxy")
            if privacy["tor"]:
                labels.append("tor")
            if privacy["relay"]:
                labels.append("relay")
            if privacy["hosting"]:
                labels.append("hosting")
            if len(privacy["service"]) > 0:
                labels.append(privacy["service"])
            for i, data in enumerate(stix_objects):
                if "ipv4-addr" in data["type"] or "ipv6-addr" in data["type"]:
                    stix_objects[i]["labels"] = labels  # Add to ipv4 or ipv6 object
        if asn:
            asn_object = stix2.AutonomousSystem(number=asn["asn"], name=asn["name"])
            stix_objects.append(asn_object)
            observable_to_asn = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "belongs-to", stix_entity["id"], asn_object.id
                ),
                relationship_type="belongs-to",
                source_ref=stix_entity["id"],
                target_ref=asn_object.id,
                confidence=self.helper.connect_confidence_level,
            )
            stix_objects.append(observable_to_asn)
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
        observable_to_country = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "located-at", stix_entity["id"], country_location.id
            ),
            relationship_type="located-at",
            source_ref=stix_entity["id"],
            target_ref=country_location.id,
            confidence=self.helper.connect_confidence_level,
        )
        stix_objects.append(observable_to_country)
        return self.helper.stix2_create_bundle(stix_objects)

    def _process_message(self, data: Dict):
        opencti_entity = data["enrichment_entity"]

        # Extract TLP and validate
        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        # Enrich the bundle with ip info
        stix_entity = data["stix_entity"]
        stix_objects = data["stix_objects"]
        # Get the geo loc from the API
        api_url = (
            "https://ipinfo.io/"
            + stix_entity["value"]
            + "/json/?token="
            + self.token.get_secret_value()
        )

        try:
            response = requests.request(
                "GET",
                api_url,
                headers={
                    "accept": "application/json",
                    "content-type": "application/json",
                },
            )
            response.raise_for_status()
            json_data = response.json()

        except requests.exceptions.HTTPError as err:
            error_status_code = getattr(err.response, "status_code", None)
            error_reason = getattr(err.response, "reason", None)

            if error_status_code == 403:
                raise ValueError(
                    f"Invalid API Token, Error {error_status_code}. Reason: {error_reason}"
                )
            elif error_status_code == 429:
                raise ValueError(
                    f"IpInfo Rate limit exceeded, Error {error_status_code}. Reason: {error_reason}"
                )
            else:
                raise ValueError(
                    f"Unexpected HTTP Error {error_status_code}. Reason: {error_reason}"
                )

        except requests.exceptions.RequestException:
            raise ConnectionError("API connection error.")

        except ValueError:
            raise ValueError("Invalid JSON in response.")

        if "country" not in json_data:
            raise ValueError("Country not found, an error occurred")
        country = pycountry.countries.get(alpha_2=json_data["country"])
        if country is None:
            raise ValueError(
                "IpInfo was not able to find a country for this IP address"
            )
        asn = {}
        privacy = {}
        if "asn" in json_data:
            asn["name"] = (
                json_data["asn"]["name"]
                if self.use_asn_name
                else json_data["asn"]["asn"]
            )
            if match := re.search(r"\d+", json_data["asn"]["asn"]):
                asn["asn"] = int(match.group())
        elif "org" in json_data:
            asn_data, name_data = json_data["org"].split(" ", 1)
            asn["name"] = name_data if self.use_asn_name else asn_data
            if match := re.search(r"\d+", asn_data):
                asn["asn"] = int(match.group())
        if "privacy" in json_data:
            privacy["vpn"] = json_data["privacy"]["vpn"]
            privacy["proxy"] = json_data["privacy"]["proxy"]
            privacy["tor"] = json_data["privacy"]["tor"]
            privacy["relay"] = json_data["privacy"]["relay"]
            privacy["hosting"] = json_data["privacy"]["hosting"]
            privacy["service"] = json_data["privacy"]["service"]
        bundle = self._generate_stix_bundle(
            stix_objects,
            stix_entity,
            country,
            json_data["city"],
            json_data["loc"],
            asn,
            privacy,
        )
        bundles_sent = self.helper.send_stix2_bundle(bundle)
        return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    try:
        ipInfoInstance = IpInfoConnector()
        ipInfoInstance.start()
    except Exception:
        traceback.print_exc()
        exit(1)
