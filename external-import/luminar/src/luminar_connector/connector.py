"""
Connect to Cognyte Luminar and ingest feeds into OpenCTI.
"""

import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
from pycti import AttackPattern as OpenCTIAttackPattern
from pycti import Campaign as OpenCTICampaign
from pycti import Identity as OpenCTIIdentity
from pycti import Incident as OpenCTIIncident
from pycti import Indicator as OpenCTIIndicator
from pycti import Location as OpenCTILocation
from pycti import Malware as OpenCTIMalware
from pycti import OpenCTIConnectorHelper
from pycti import Report as OpenCTIReport
from pycti import StixCoreRelationship
from pycti import ThreatActor as OpenCTIThreatActor
from pycti import Tool as OpenCTITool
from pycti import Vulnerability as OpenCTIVulnerability
from stix2 import (
    URL,
    AttackPattern,
    Campaign,
    Directory,
    DomainName,
    EmailAddress,
    File,
    Identity,
    Incident,
    Indicator,
    IPv4Address,
    IPv6Address,
    Location,
    Malware,
    Mutex,
    Relationship,
    Report,
    Software,
    ThreatActor,
    Tool,
    UserAccount,
    Vulnerability,
    WindowsRegistryKey,
)
from stix2 import parse as stix_parser

from .config_loader import ConfigConnector

HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "accept": "application/json",
}
TIMEOUT = 60.0
LUMINAR_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


IOC_MAPPING = {
    "ipv4-addr": IPv4Address,
    "ipv6-addr": IPv6Address,
    "domain-name": DomainName,
    "url": URL,
    "file": File,
    "email-addr": EmailAddress,
    "windows-registry-key": WindowsRegistryKey,
    "mutex": Mutex,
    "directory": Directory,
}
LUMINARCYBERFEEDS_X_STIX2 = {
    "malware": Malware,
    "threat-actor": ThreatActor,
    "location": Location,
    "vulnerability": Vulnerability,
    "identity": Identity,
    "campaign": Campaign,
    "software": Software,
    "tool": Tool,
    "attack-pattern": AttackPattern,
}


STIX_PARSER = re.compile(
    r"([\w-]+?):(\w.+?) (?:[!><]?=|IN|MATCHES|LIKE) '(.*?)' *[" + r"OR|AND|FOLLOWEDBY]?"
)
RELATIONSHIP_PROP = {"x_opencti_description": "Relationship by Cognyte Luminar"}


class ConnectorLuminar:
    """
    Class to manage Luminar API interactions.
    """

    STATUS_MESSAGES = {
        400: "Bad request. The server could not understand the request due to invalid syntax.",
        401: "Unauthorized. The client must authenticate itself to get the requested response.",
        403: "Forbidden. The client does not have access rights to the content.",
        404: "Not Found. The server can not find the requested resource.",
        408: "Request Timeout. The server would like to shut down this unused connection.",
        429: "Too Many Requests. The user has sent too many requests in a given amount of time.",
        500: "Internal Server Error. The server has encountered a situation it doesn't "
        " know how to handle.",
        502: "Bad Gateway. The server was acting as a gateway or proxy and received an invalid "
        "response from the upstream server.",
        503: "Service Unavailable. The server is not ready to handle the request.",
    }

    def __init__(self) -> None:
        # pylint: disable=too-many-positional-arguments

        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)

        # Extra config
        self.luminar_base_url = self.config.luminar_base_url
        self.luminar_account_id = self.config.luminar_account_id
        self.luminar_client_id = self.config.luminar_client_id
        self.luminar_client_secret = self.config.luminar_client_secret
        self.initial_fetch_date = self.config.initial_fetch_date
        self.create_observable = self.config.create_observable
        self.duration_period = self.config.duration_period
        self.author = Identity(
            id=OpenCTIIdentity.generate_id(
                name="Cognyte Luminar", identity_class="organization"
            ),
            name="Cognyte Luminar",
            identity_class="organization",
            description="Cognyte Luminar Threat Intelligence feeds for IOC, Leaked Records and Cyberfeeds",
        )
        self.x_opencti_score = 80

        self.payload = {
            "client_id": self.luminar_client_id,
            "client_secret": self.luminar_client_secret,
            "grant_type": "client_credentials",
            "scope": "externalAPI/stix.readonly",
        }
        self.req_headers = HEADERS

    def access_token(self) -> Tuple[Union[bool, str], str]:
        """
        Request an access token from the Luminar API.

        :return: A tuple containing either the access token (str) or False,
                and a status message.
        """
        req_url = f"{self.luminar_base_url}/externalApi/v2/realm/{self.luminar_account_id}/token"
        try:
            response = requests.post(
                req_url, headers=self.req_headers, data=self.payload, timeout=TIMEOUT
            )
            response.raise_for_status()
        except requests.HTTPError as http_err:
            status_code = http_err.response.status_code if http_err.response else 0
            message = self.STATUS_MESSAGES.get(
                status_code, f"HTTP error occurred: {http_err}"
            )
            self.helper.connector_logger.error(f"HTTP error occurred: {http_err}")
            return False, message
        except requests.RequestException as req_err:
            self.helper.connector_logger.error(f"Request exception: {req_err}")
            return False, "An error occurred while making HTTP request"
        except Exception as err:
            self.helper.connector_logger.error(f"Unexpected error: {err}")
            return False, f"Failed to connect to Luminar API... Error is {err}"

        # Process successful response
        access_token = response.json().get("access_token")
        if access_token:
            return access_token, "Luminar API Connected successfully"
        return False, "Access token not found in response"

    def get_taxi_collections(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Fetches TAXII collections from the Luminar API and returns a mapping of
        collection aliases to their IDs.

        This function sends a GET request to retrieve TAXII collections and extracts
        the alias-ID mapping.
        If an error occurs during the request, it logs the error and returns an empty
        dictionary.

        :param headers: Dictionary containing authentication headers for the API request.
        :type headers: dict
        :return: A dictionary mapping collection aliases to their corresponding IDs.
        :rtype: dict
        """
        taxii_collection_ids = {}
        try:
            req_url = f"{self.luminar_base_url}/externalApi/taxii/collections/"
            resp = requests.get(req_url, headers=headers, timeout=TIMEOUT)
            resp.raise_for_status()
            collections_data = resp.json()["collections"]
            self.helper.connector_logger.info(
                f"Cognyte Luminar collections: {collections_data}"
            )

            # Store collection alias and id mapping
            for collection in collections_data:
                taxii_collection_ids[collection.get("alias")] = collection.get("id")
        except Exception as e:
            self.helper.connector_logger.info(f"Error fetching collections: {e}")
        return taxii_collection_ids

    def generate_pycti_id(self, obj: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate a PyCTI ID for the given STIX object.

        :param obj: A dictionary representing a STIX object (e.g., malware, threat-actor).
        :return: A stix object with 'id' containing the generated PyCTI ID for supported objects.
        """
        obj_type = obj.get("type", "")
        name = obj.get("name", "luminar")
        if obj_type == "malware":
            obj["id"] = OpenCTIMalware.generate_id(name)
        elif obj_type == "threat-actor":
            obj["id"] = OpenCTIThreatActor.generate_id(name, "organization")
        elif obj_type == "location":
            obj["id"] = OpenCTILocation.generate_id(name, "country")
        elif obj_type == "vulnerability":
            obj["id"] = OpenCTIVulnerability.generate_id(name)
        elif obj_type == "identity":
            obj["id"] = OpenCTIIdentity.generate_id(
                name, identity_class=obj.get("identity_class", "organization")
            )
        elif obj_type == "campaign":
            obj["id"] = OpenCTICampaign.generate_id(name)
        elif obj_type == "tool":
            obj["id"] = OpenCTITool.generate_id(name)
        elif obj_type == "attack-pattern":
            obj["id"] = OpenCTIAttackPattern.generate_id(name, "attack-pattern")
        return obj

    def get_collection_objects(
        self, headers: Dict[str, str], collection: str, params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Fetches objects from Luminar collection using pagination and retry logic.

        :param headers: Authentication headers.
        :param collection: TAXII collection ID.
        :param params: Query parameters for the API.
        :return: List of retrieved objects.
        """
        parameters = params.copy()
        collection_objects = []
        max_retries = 3

        while True:
            retry_count = 0
            refreshed_token = False

            while retry_count < max_retries:
                resp = requests.get(
                    f"{self.luminar_base_url}/externalApi/taxii/collections/{collection}/objects/",
                    params=parameters,
                    headers=headers,
                    timeout=TIMEOUT,
                )

                if resp.status_code == 200:
                    response_json = resp.json()
                    collection_objects.extend(response_json.get("objects", []))

                    next_page = response_json.get("next")
                    if next_page:
                        parameters["next"] = next_page
                    else:
                        self.helper.connector_logger.info(
                            f"Fetched all objects from collection: {collection}"
                        )
                        return collection_objects
                    break  # Proceed to next pagination page

                if resp.status_code == 401:
                    if refreshed_token:
                        self.helper.connector_logger.warning(
                            "Received 401 even after refreshing token. Aborting."
                        )
                        return collection_objects

                    self.helper.connector_logger.info(
                        f"Access token expired. Status code: 401, response: {resp.text}. Refreshing token..."
                    )
                    access_token, _ = self.access_token()
                    headers = {"Authorization": f"Bearer {access_token}"}
                    refreshed_token = True
                    retry_count += 1

                else:
                    self.helper.connector_logger.error(
                        f"Failed to fetch objects from collection {collection}. "
                        f"Status code: {resp.status_code}, Response: {resp.text}"
                    )
                    return collection_objects

            else:
                self.helper.connector_logger.error(
                    f"Exceeded max retries ({max_retries}) for collection {collection}."
                )
                return collection_objects

    def get_timestamp(self) -> str:
        """
        Retrieves the current timestamp in UTC format with microsecond precision.

        This function fetches the current time in UTC, formats it into an ISO 8601 string
        with microsecond precision, and appends a 'Z' to indicate that the time is in UTC.

        Returns:
            str: The current timestamp in UTC with microsecond precision, formatted as
                'YYYY-MM-DDTHH:MM:SS.mmmmmmZ'.
        """
        current_time = datetime.now(timezone.utc)
        return (
            current_time.strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{current_time.microsecond:06d}Z"
        )

    def check_created_date(self, obj_date: str, from_date: datetime) -> bool:
        """
        Validates whether the given object creation date is greater than or equal
        to the specified 'from_date'.

        :param obj_date: A string representing the creation date of the object in
                        ISO 8601 format ("%Y-%m-%dT%H:%M:%S.%fZ").
        :param from_date: A datetime object representing the threshold date.
        :return: True if obj_date is valid and greater than or equal to from_date,
                otherwise False.
        """
        try:
            return datetime.strptime(obj_date, LUMINAR_DATE_FORMAT) >= from_date
        except Exception as ex:
            self.helper.connector_logger.info(f"Invalid date format: {obj_date}; {ex}")
            return False

    def filtered_records(
        self, records: List[Dict[str, Any]], from_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Filter records based on their creation date.

        :param records: List of records to filter.
        :param from_date: Filter date for processing new records.
        :return: List of filtered records.
        """
        return [
            record
            for record in records
            if not record.get("created")
            or self.check_created_date(record["created"], from_date)
        ]

    def make_relationships(self, records: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Creates a dictionary mapping target references to a list of source references.

        :param records: A list of relationship dictionaries, each containing 'source_ref'
          and 'target_ref'.
        :return: A dictionary where each key is a 'target_ref' and the value is a list of
          associated 'source_ref' values.
        """
        relationships: Dict[str, List[str]] = {}

        for relationship in records:
            target_ref = relationship.get("target_ref")
            source_ref = relationship.get("source_ref")

            if target_ref and source_ref:
                relationships.setdefault(target_ref, []).append(source_ref)

        return relationships

    def create_lookup_dict(
        self, list_of_dicts: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Converts a list of dictionaries into a lookup dictionary indexed by 'id'.

        :param list_of_dicts: List of dictionaries to process.
        :return: A dictionary where keys are 'id' values (str) and
        values are the corresponding dictionaries.
        """
        return {dict_item["id"]: dict_item for dict_item in list_of_dicts}

    def get_from_extensions(self, key: str, obj: Dict[str, Any]) -> Optional[Any]:
        """
        Returns the value from the "extensions" field if it exists, else returns None.

        :param key: The key to search for in the "extensions" field.
        :param obj: The dictionary object that may contain an "extensions" field.
        :return: The value associated with the given key, or None if the key is not found.
        """
        if "extensions" in obj:
            for k, v in obj["extensions"].items():
                if k.startswith("extension-definition--") and isinstance(v, dict):
                    if key in v:
                        return v.get(key)
        return None

    def process_iocs(self, from_date_str, records):
        """
        Processes IOC records related to malware or threat actors into STIX 2.1 objects.

        Args:
            from_date_str (str): Date string to filter records from.
            records (list): List of raw IOC records including indicators and relationships.

        Returns:
            list: STIX 2.1 objects including malware/threat-actor entities and related indicators.
        """
        from_date = datetime.strptime(from_date_str, LUMINAR_DATE_FORMAT)
        filtered = self.filtered_records(records, from_date)
        lookup = self.create_lookup_dict(filtered)
        relationship_records = [r for r in filtered if r.get("type") == "relationship"]
        relationships = self.make_relationships(relationship_records)

        ioc_bundle = []
        for key, group in relationships.items():
            parent = lookup.get(key, {})
            children = list(
                filter(None, [lookup.get(item_id, {}) for item_id in group])
            )
            if (
                parent
                and parent.get("type") in ["malware", "threat-actor"]
                and children
            ):
                luminar_threat_score = self.get_from_extensions(
                    "luminar_threat_score", parent
                )

                labels = (
                    [f"luminar_threat_score: {luminar_threat_score}"]
                    if luminar_threat_score
                    else []
                )
                parent["created_by_ref"] = self.author.id
                parent_copy = parent.copy()
                parent_copy.pop("id", None)
                if parent.get("type") == "malware":
                    parent_stix_obj = Malware(
                        **parent_copy,
                        id=OpenCTIMalware.generate_id(parent.get("name", "luminar")),
                        labels=labels,
                        description="Luminar IOC",
                    )
                else:
                    parent_stix_obj = ThreatActor(
                        **parent_copy,
                        id=OpenCTIThreatActor.generate_id(
                            parent.get("name", "luminar"), "organization"
                        ),
                        labels=labels,
                        description="Luminar IOC",
                    )

                ioc_bundle.append(parent_stix_obj)
                for c in children:
                    if c.get("type") == "indicator":
                        self.process_opencti_indicator(c, parent_stix_obj, ioc_bundle)

        return ioc_bundle

    def process_leaked(self, from_date_str, leaked_records):
        """
        Processes leaked credential and malware records into STIX 2.1 objects.

        Args:
            from_date_str (str): Date string to filter records from.
            leaked_records (list): List of raw leaked data records.

        Returns:
            list: STIX 2.1 objects including incidents, malware, user accounts, and relationships.
        """
        from_date = datetime.strptime(from_date_str, LUMINAR_DATE_FORMAT)
        filtered = self.filtered_records(leaked_records, from_date)
        lookup = self.create_lookup_dict(filtered)
        relationship_records = [r for r in filtered if r.get("type") == "relationship"]
        relationships = self.make_relationships(relationship_records)
        leaked_bundle = []
        for key, group in relationships.items():
            parent = lookup.get(key, {})
            children = list(
                filter(None, [lookup.get(item_id, {}) for item_id in group])
            )
            if parent and parent.get("type") == "incident" and children:
                parent["created_by_ref"] = self.author.id
                luminar_threat_score = self.get_from_extensions(
                    "luminar_threat_score", parent
                )
                labels = (
                    [f"luminar_threat_score: {luminar_threat_score}"]
                    if luminar_threat_score
                    else []
                )
                parent.pop("id", None)  # Remove id to avoid conflicts
                parent_stix_obj = Incident(
                    **parent,
                    id=OpenCTIIncident.generate_id(
                        parent.get("name", "luminar"), created=parent.get("created")
                    ),
                    source="Cognyte Luminar",
                    incident_type="compromise",
                    severity="high",
                    labels=labels,
                    allow_custom=True,
                )
                leaked_bundle.append(parent_stix_obj)
                custom_prop = {
                    "x_opencti_created_by_ref": self.author.id,
                    "x_opencti_score": 100,
                }
                for c in children:
                    c.pop("id", None)
                    if c.get("type") == "malware":
                        malware_stix_obj = Malware(
                            **c,
                            id=OpenCTIMalware.generate_id(c.get("name", "luminar")),
                            labels=labels,
                            description="Luminar Leaked Credentials",
                            created_by_ref=self.author.id,
                        )
                        mal_rel = Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", malware_stix_obj.id, parent_stix_obj.id
                            ),
                            source_ref=malware_stix_obj.id,
                            target_ref=parent_stix_obj.id,
                            relationship_type="related-to",
                            created_by_ref=self.author.id,
                            custom_properties=RELATIONSHIP_PROP,
                            allow_custom=True,
                        )
                        leaked_bundle.extend([malware_stix_obj, mal_rel])
                    elif c.get("type") == "user-account":
                        luminar_plan_terms = self.get_from_extensions(
                            "monitoring_plan_terms", c
                        )
                        luminar_source = self.get_from_extensions("source", c)
                        luminar_url = self.get_from_extensions("url", c)
                        luminar_is_fresh = self.get_from_extensions(
                            "credential_is_fresh", c
                        )
                        labels = []
                        if luminar_plan_terms:
                            labels.append(
                                f"luminar_monitoring_plan_terms:{';'.join(luminar_plan_terms)}"
                            )
                        if luminar_source:
                            labels.append(f"luminar_source: {luminar_source}")
                        if luminar_url:
                            labels.append(f"luminar_url: {luminar_url}")
                        if luminar_is_fresh:
                            labels.append(
                                f"luminar_credential_is_fresh: {luminar_is_fresh}"
                            )
                        if labels:
                            custom_prop["x_opencti_labels"] = labels
                        custom_prop["x_opencti_description"] = (
                            "Luminar Leaked Credentials"
                        )
                        user_stix_obj = UserAccount(
                            **c,
                            custom_properties=custom_prop,
                        )
                        user_rel = Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", user_stix_obj.id, parent_stix_obj.id
                            ),
                            source_ref=user_stix_obj.id,
                            target_ref=parent_stix_obj.id,
                            relationship_type="related-to",
                            created_by_ref=self.author.id,
                            custom_properties=RELATIONSHIP_PROP,
                            allow_custom=True,
                        )
                        leaked_bundle.extend([user_stix_obj, user_rel])
        return leaked_bundle

    def process_opencti_indicator(
        self, obj, parent_obj, bundle, ref_bundle=None, from_cyberfeeds=False
    ):
        """
        Processes an indicator object and adds it to a STIX bundle.

        Args:
            obj (dict): The indicator object.
            parent_obj (Optional[object]): The parent STIX object (e.g., Report) for relationship.
            bundle (list): The main list to collect STIX objects.
            ref_bundle (list, optional): Reference list for object_refs (used with reports).
            from_cyberfeeds (bool): Flag to indicate if the source is Cyberfeeds.

        Returns:
            None
        """
        try:
            stix_parser(obj)
        except ValueError as ve:
            if "'valid_until' must be greater than 'valid_from'" in str(ve):
                obj.pop("valid_until")
            else:
                self.helper.connector_logger.error(
                    f"Skipping Invalid indicator: {str(obj)}"
                )
                return
        except Exception as e:
            self.helper.connector_logger.error(
                f"Skipping Invalid indicator: {str(obj)} as {str(e)}"
            )
            return
        obj["created_by_ref"] = self.author.id
        if not obj.get("pattern"):
            self.helper.connector_logger.error(
                f"Skipping Invalid indicator: {str(obj)} as it has no pattern"
            )
            return
        obj_copy = obj.copy()
        obj_copy.pop("id", None)  # Remove id to avoid conflicts
        open_cti_indicator = Indicator(
            **obj_copy,
            id=OpenCTIIndicator.generate_id(obj.get("pattern", "luminar")),
            description=obj.get("name", "Luminar IOC"),
            custom_properties={
                "x_opencti_score": (
                    90
                    if "Known Malicious IPs" in obj.get("name", "")
                    else self.x_opencti_score
                )
            },
            allow_custom=True,
        )
        if from_cyberfeeds:
            ref_bundle.append(open_cti_indicator.id)
            bundle.append(open_cti_indicator)
        else:
            ind_rel = Relationship(
                id=StixCoreRelationship.generate_id(
                    "indicates", open_cti_indicator.id, parent_obj.id
                ),
                source_ref=open_cti_indicator.id,
                target_ref=parent_obj.id,
                relationship_type="indicates",
                created_by_ref=self.author.id,
                custom_properties=RELATIONSHIP_PROP,
                allow_custom=True,
            )
            bundle.extend([open_cti_indicator, ind_rel])

        if self.create_observable:
            custom_prop = {
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_score": (
                    90
                    if "Known Malicious IPs" in obj.get("name", "")
                    else self.x_opencti_score
                ),
                "x_opencti_description": "Luminar IOC",
            }

            open_cti_observable = None
            pattern = obj.get("pattern")
            if isinstance(pattern, str):
                try:
                    matches = STIX_PARSER.findall(pattern)
                except TypeError as err:
                    self.helper.connector_logger.error(
                        f"Error on pattern: {pattern} and {err}"
                    )
                    return

                for match in matches:
                    stix_type, stix_property, value = match
                    if stix_type in [
                        "ipv4-addr",
                        "ipv6-addr",
                        "domain-name",
                        "url",
                        "email-addr",
                    ]:
                        open_cti_observable = IOC_MAPPING.get(stix_type)(
                            value=value, custom_properties=custom_prop
                        )
                    elif stix_type == "file":
                        if "hashes" in stix_property:
                            hash_type = stix_property.split("hashes.")[1].replace(
                                "'", ""
                            )
                            open_cti_observable = File(
                                hashes={hash_type: value},
                                custom_properties=custom_prop,
                            )
                        elif stix_property == "name":
                            open_cti_observable = File(
                                name=value,
                                custom_properties=custom_prop,
                            )
                        elif stix_property == "size":

                            open_cti_observable = File(
                                size=value,
                                custom_properties=custom_prop,
                            )

                    elif stix_type == "mutex":
                        open_cti_observable = Mutex(
                            name=value, custom_properties=custom_prop
                        )
                    elif stix_type == "directory":
                        open_cti_observable = Directory(
                            path=value, custom_properties=custom_prop
                        )
                    if open_cti_observable:
                        obs_rel = Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on",
                                open_cti_indicator.id,
                                open_cti_observable.id,
                            ),
                            source_ref=open_cti_indicator.id,
                            target_ref=open_cti_observable.id,
                            relationship_type="based-on",
                            created_by_ref=self.author.id,
                            custom_properties=RELATIONSHIP_PROP,
                            allow_custom=True,
                        )
                        bundle.extend([open_cti_observable, obs_rel])

            else:
                self.helper.connector_logger.error(
                    f"Unexpected pattern type: {pattern} in children: {str(obj)}"
                )

    def get_description(self, obj):
        """
        Returns the object's description or a default value.

        Args:
            obj (dict): A STIX-like object.

        Returns:
            str: The description string.
        """
        return f"{obj['description']}" if "description" in obj else "Luminar Cyberfeeds"

    def process_cyberfeeds(self, from_date_str, cyber_records):
        """
        Converts filtered luminar feeds records into STIX 2.1 objects.

        Args:
            from_date_str (str): Date string to filter records from.
            cyber_records (list): List of luminar cyberfeeds records.

        Returns:
            list: STIX 2.1 objects including indicators, reports, and relationships.
        """
        from_date = datetime.strptime(from_date_str, LUMINAR_DATE_FORMAT)
        filtered = self.filtered_records(cyber_records, from_date)
        lookup = self.create_lookup_dict(filtered)
        relationship_records = [r for r in filtered if r.get("type") == "relationship"]
        reports_records = [r for r in filtered if r.get("type") == "report"]
        custom_prop = {
            "x_opencti_created_by_ref": self.author.id,
            "x_opencti_score": self.x_opencti_score,
        }

        cyberfeeds_bundle = []
        for obj in relationship_records:
            source_rec = lookup.get(obj["source_ref"])
            target_rec = lookup.get(obj["target_ref"])
            if source_rec and target_rec:
                if (
                    source_rec.get("type") in LUMINARCYBERFEEDS_X_STIX2
                    and target_rec.get("type") in LUMINARCYBERFEEDS_X_STIX2
                ):
                    source_rec["description"] = self.get_description(source_rec)
                    target_rec["description"] = self.get_description(target_rec)
                    source_rec_copy = source_rec.copy()
                    target_rec_copy = target_rec.copy()
                    source_stix = LUMINARCYBERFEEDS_X_STIX2[source_rec["type"]](
                        custom_properties=custom_prop,
                        allow_custom=True,
                        **self.generate_pycti_id(source_rec_copy),
                    )
                    target_stix = LUMINARCYBERFEEDS_X_STIX2[target_rec["type"]](
                        custom_properties=custom_prop,
                        allow_custom=True,
                        **self.generate_pycti_id(target_rec_copy),
                    )

                    rel = Relationship(
                        id=StixCoreRelationship.generate_id(
                            obj.get("relationship_type", "related-to"),
                            source_stix.id,
                            target_stix.id,
                        ),
                        source_ref=source_stix.id,
                        target_ref=target_stix.id,
                        relationship_type=obj.get("relationship_type", ""),
                        created_by_ref=self.author.id,
                        custom_properties=RELATIONSHIP_PROP,
                        allow_custom=True,
                    )
                    cyberfeeds_bundle.extend([source_stix, target_stix, rel])
        for rep in reports_records:
            object_refs_stix = []
            for ref in rep.get("object_refs", []):
                ref_type = ref.split("--")[0]
                ref_obj = lookup.get(ref, {})
                if ref_type in LUMINARCYBERFEEDS_X_STIX2 and ref_obj:
                    ref_obj["created_by_ref"] = self.author.id
                    ref_obj["description"] = self.get_description(ref_obj)
                    ref_obj_copy = (
                        ref_obj.copy()
                    )  # Create a copy to avoid modifying the original
                    ref_stix = LUMINARCYBERFEEDS_X_STIX2[ref_type](
                        custom_properties=custom_prop,
                        allow_custom=True,
                        **self.generate_pycti_id(ref_obj_copy),
                    )
                    object_refs_stix.append(ref_stix.id)
                    cyberfeeds_bundle.append(ref_stix)
                elif ref_type == "indicator" and ref_obj:
                    ref_obj_copy = ref_obj.copy()
                    self.process_opencti_indicator(
                        ref_obj_copy, None, cyberfeeds_bundle, object_refs_stix, True
                    )

            if object_refs_stix:
                rep["object_refs"] = object_refs_stix
                rep.pop("id", None)  # Remove id to avoid conflicts
                rep["created_by_ref"] = self.author.id
                cyberfeeds_bundle.append(
                    Report(
                        id=OpenCTIReport.generate_id(
                            rep.get("name", "luminar"), rep.get("published")
                        ),
                        **rep,
                        custom_properties={"x_opencti_score": self.x_opencti_score},
                        allow_custom=True,
                    )
                )
        return cyberfeeds_bundle

    def process_message(self):
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )
        try:
            current_state = self.helper.get_state()
            last_run = None
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

            self.helper.connector_logger.info("Connecting to Cognyte Luminar...")
            access_token, message = self.access_token()
            if not access_token:
                self.helper.connector_logger.error(
                    f"Failed to get access token: {message}"
                )
                return

            headers = {"Authorization": f"Bearer {access_token}"}
            taxii_collection = self.get_taxi_collections(headers)
            if not taxii_collection:
                return

            next_checkpoint = self.get_timestamp()

            from_date = last_run or self.initial_fetch_date + "T00:00:00.000000Z"

            params = {"limit": 9999}
            params["added_after"] = from_date
            self.helper.connector_logger.info(f"Fetching Luminar data from {from_date}")

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = self.helper.connect_name

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            ioc_records = self.get_collection_objects(
                headers, taxii_collection["iocs"], params
            )
            self.helper.connector_logger.info(
                f"IOC records fetched: {len(ioc_records)}"
            )

            leaked_records = self.get_collection_objects(
                headers, taxii_collection["leakedrecords"], params
            )
            self.helper.connector_logger.info(
                f"Leaked records fetched: {len(leaked_records)}"
            )

            cyberfeeds_records = self.get_collection_objects(
                headers, taxii_collection["cyberfeeds"], params
            )
            self.helper.connector_logger.info(
                f"cyberfeeds records fetched: {len(cyberfeeds_records)}"
            )

            ioc_processed_records = self.process_iocs(from_date, ioc_records)
            leaked_processed_records = self.process_leaked(from_date, leaked_records)
            cyberfeeds_processed_records = self.process_cyberfeeds(
                from_date, cyberfeeds_records
            )
            if (
                len(
                    ioc_processed_records
                    + leaked_processed_records
                    + cyberfeeds_processed_records
                )
                > 0
            ):
                all_bundle = self.helper.stix2_create_bundle(
                    ioc_processed_records
                    + leaked_processed_records
                    + cyberfeeds_processed_records
                    + [self.author],
                )

                self.helper.connector_logger.info(
                    "[CONNECTOR] Running connector...",
                    {"connector_name": self.helper.connect_name},
                )
                bundles_sent = self.helper.send_stix2_bundle(
                    bundle=all_bundle, update=True, work_id=work_id
                )
                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": {str(len(bundles_sent))}},
                )
            else:
                self.helper.connector_logger.info("No new data to import!")

            self.helper.set_state({"last_run": next_checkpoint})

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(next_checkpoint)
            )

            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.duration_period,
        )
