import os
import yaml
import logging
import requests

from dateutil import parser
from typing import Optional
from pydantic import BaseModel
from urllib.parse import urljoin

from pycti import OpenCTIConnectorHelper, get_config_variable

logger = logging.getLogger(__name__)


class MalBeaconConnector:
    """Malbeacon connector class"""

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL", ["connector", "confidence_level"], config
        )
        self.api_key = get_config_variable(
            "MALBEACON_API_KEY", ["malbeacon", "api_key"], config
        )

        self.author = self.helper.api.identity.create(
            name="Malbeacon",
            type="Organization",
            description="""The first system of its kind, MalBeacon implants \
            beacons via malware bot check-in traffic. Adversaries conducting \
            campaigns in the wild who are logging in to these malware C2 \
            panels can now be tracked. MalBeacon is a tool for the good guys \
            that provides additional intelligence on attack attribution.""",
            update=True,
        )

    def _process_observable(self, observable) -> str:
        logger.info(f"processing observable: {observable}")
        # Extract IPv4, IPv6, Hostname and Domain from entity data
        obs_val = observable["observable_value"]
        obs_typ = observable["entity_type"]
        obs_id = observable["id"]

        if obs_typ == "Domain-Name":
            self._process_c2(obs_val, obs_id)
        elif obs_typ in ["IPv4-Addr", "IPv6-Addr"]:
            self._process_c2(obs_val, obs_id)
        elif obs_typ in "Email-Address":
            # TODO: not implemented yet
            pass
        else:
            return "no information found on malbeacon"

        return "observable value found on malbeacon API and knowledge added"

    def _process_message(self, data) -> list:
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        return self._process_observable(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)

    ################################
    # Helper Functions
    ################################

    def _api_call(self, url_path):
        api_base_url = "https://api.malbeacon.com/v1/"
        url = urljoin(api_base_url, url_path)

        try:
            r = requests.get(url, headers={"X-Api-Key": self.api_key})
        except requests.exceptions.RequestException as e:
            logger.error(f"error in malbeacon api request: {e}")
            return None

        return r.json()

    def _process_c2(self, obs_value, obs_id):
        already_processed = []

        reference = self.helper.api.external_reference.create(
            source_name="Malbeacon C2 Domains",
            url="https://malbeacon.com/illuminate",
            description="Found in Malbeacon C2 Domains",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=obs_id, external_reference_id=reference["id"]
        )

        data = self._api_call("c2/c2/" + obs_value)

        # If the API returns a JSON document with a message
        # there probably has been an error or no information
        # could be retreived from the Malbeacon database
        try:
            api_error = data["message"]
            logger.error(f"Error in API request: {api_error}")
            return None
        except (ValueError, TypeError):
            pass

        try:
            for entry in data:
                c2_beacon = C2Beacon.parse_obj(entry)
                logger.info(
                    f"Processing: {c2_beacon.cti_date} {c2_beacon.actorip} {c2_beacon.actorhostname}"
                )

                ######################################################
                # Process what we know about the actors infrastructure
                ######################################################

                if (
                    c2_beacon.actorip != "NA"
                    and c2_beacon.actorip not in already_processed
                ):
                    self.helper.api.stix_cyber_observable.create(
                        simple_observable_key="IPv4-Addr.value",
                        simple_observable_value=c2_beacon.actorip,
                        simple_observable_description=f"Malbeacon Actor IP Address for C2 {obs_value}",
                        createdBy=self.author["id"],
                        x_opencti_score=int(self.confidence_level),
                        createIndicator=True,
                    )

                    # TODO: find and implement meaningful relationships
                    # self.helper.api.stix_core_relationship.create(
                    #    fromId=obs_id,
                    #    toId=actor_ip_obs["id"],
                    #    relationship_type="based-on",
                    #    createdBy=self.author["id"],
                    # )

                    if c2_beacon.actorhostname != "NA":
                        self.helper.api.stix_cyber_observable.create(
                            simple_observable_key="Domain-Name.value",
                            simple_observable_value=c2_beacon.actorhostname,
                            simple_observable_description=f"Malbeacon Actor DomainName for C2 {obs_value}",
                            createdBy=self.author["id"],
                            x_opencti_score=int(self.confidence_level),
                            createIndicator=True,
                        )

                    # TODO: find and implement meaningful relationships
                    #    self.helper.api.stix_core_relationship.create(
                    #        fromId=actor_domain_obs["id"],
                    #        toId=actor_ip_obs["id"],
                    #        relationship_type="resolves-to",
                    #        createdBy=self.author["id"],
                    #    )

                    # Make sure we only process this specific IP once
                    already_processed.append(c2_beacon.actorip)

        except Exception as err:
            logger.error(f"error processing c2 beacons: {err}")
            return None


################################
# Models
################################


class C2Beacon(BaseModel):
    """MalBeacon C2 Beacon base model"""

    tstamp: Optional[str]  # format: 2020-10-22 09:04:40
    actorasnorg: Optional[str]
    actorcity: Optional[str]
    actorcountrycode: Optional[str]
    actorhostname: Optional[str]
    actorip: Optional[str]
    actorloc: Optional[str]
    actorregion: Optional[str]
    actortimezone: Optional[str]
    c2: Optional[str]
    c2asnorg: Optional[str]
    c2city: Optional[str]
    c2countrycode: Optional[str]
    c2domain: Optional[str]
    c2domainresolved: Optional[str]
    c2hostname: Optional[str]
    c2loc: Optional[str]
    c2region: Optional[str]
    c2timezone: Optional[str]
    cookie_id: Optional[str]
    useragent: Optional[str]
    tags: Optional[str]

    @property
    def cti_tags(self) -> list:
        return self.tags.split(",")

    @property
    def cti_date(self):
        return parser.parse(self.tstamp).strftime("%Y-%m-%dT%H:%M:%S+00:00")


class EmailBeacon(BaseModel):
    """Malbeacon Email Beacon base model"""

    tstamp: Optional[str]  # format: 2020-10-22 09:04:40
    emailaddress: Optional[str]
    cookie_id: Optional[str]
    useragent: Optional[str]
    tags: Optional[str]
    malhashes: Optional[str]
    actorip: Optional[str]
    actorcity: Optional[str]
    actorregion: Optional[str]
    actorcountrycode: Optional[str]
    actorasnorg: Optional[str]
    actorhostname: Optional[str]
    actorloc: Optional[str]
    actortimezone: Optional[str]
    referrer: Optional[str]
    refdomain: Optional[str]
    refdomainresolved: Optional[str]
    refcity: Optional[str]
    refregion: Optional[str]
    refcountrycode: Optional[str]
    reftimezone: Optional[str]
    refasnorg: Optional[str]
    refloc: Optional[str]
    refhostname: Optional[str]

    @property
    def cti_tags(self) -> list:
        return self.tags.split(",")

    @property
    def cti_hashes(self) -> list:
        return self.malhashes.split(",")

    @property
    def cti_date(self):
        return parser.parse(self.tstamp).strftime("%Y-%m-%dT%H:%M:%S+00:00")


if __name__ == "__main__":
    MalBeaconInstance = MalBeaconConnector()
    MalBeaconInstance.start()
