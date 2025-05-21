"""
Connect to Cognyte Luminar and ingest feeds into OpenCTI.
"""

import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
import yaml
from pycti import OpenCTIConnectorHelper, StixCoreRelationship, get_config_variable
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

HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "accept": "application/json",
}
TIMEOUT = 60.0
LUMINAR_BASE_URL = "https://www.cyberluminar.com"
LUMINAR_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

LUMINARIOCFEEDS_X_STIX2 = {"malware": Malware, "threat-actor": ThreatActor}
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


class LuminarManager:
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

        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.luminar_base_url = get_config_variable(
            "LUMINAR_BASE_URL",
            ["luminar", "base_url"],
            config,
            default=LUMINAR_BASE_URL,
        )
        self.luminar_account_id = get_config_variable(
            "LUMINAR_ACCOUNT_ID", ["luminar", "account_id"], config
        )
        self.luminar_client_id = get_config_variable(
            "LUMINAR_CLIENT_ID", ["luminar", "client_id"], config
        )
        self.luminar_client_secret = get_config_variable(
            "LUMINAR_CLIENT_SECRET", ["luminar", "client_secret"], config
        )
        self.initial_fetch_date = get_config_variable(
            "LUMINAR_INITIAL_FETCH_DATE",
            ["luminar", "initial_fetch_date"],
            config,
        )
        self.create_observable = get_config_variable(
            "LUMINAR_CREATE_OBSERVABLE",
            ["luminar", "create_observable"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Cognyte Luminar",
            description="Cognyte Luminar Threat Intelligence feeds for IOC, Leaked Records and Cyberfeeds",
        )
        self.duration_interval = get_config_variable(
            "CONNECTOR_DURATION_INTERVAL",
            ["luminar", "duration_interval"],
            config,
            default=1,
        )
        self.x_opencti_score = 80
        self.confidence = 80

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

        :return: Tuple[Union[bool, str], str]
            The access token (if successful) or False (if unsuccessful),
            and a message indicating the status of the request.
        """
        req_url = f"{self.luminar_base_url}/externalApi/v2/realm/{self.luminar_account_id}/token"
        try:
            response = requests.post(
                req_url, headers=self.req_headers, data=self.payload, timeout=TIMEOUT
            )
            response.raise_for_status()
            access_token = response.json().get("access_token")
            if access_token:
                return access_token, "Luminar API Connected successfully"
            return False, "Access token not found in response"
        except requests.HTTPError as http_err:
            self.helper.log_error(f"HTTP error occurred: {http_err}")
            return False, self.STATUS_MESSAGES.get(
                response.status_code, "HTTP error occurred"
            )
        except requests.RequestException as req_err:
            self.helper.log_error(f"Request exception: {req_err}")
            return False, "An error occurred while making HTTP request"
        except Exception as err:
            self.helper.log_error(f"Unexpected error: {err}")
            return False, f"Failed to connect to Luminar API... Error is {err}"

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
            self.helper.log_info(f"Cognyte Luminar collections: {collections_data}")

            # Store collection alias and id mapping
            for collection in collections_data:
                taxii_collection_ids[collection.get("alias")] = collection.get("id")
        except Exception as e:
            self.helper.log_info(f"Error fetching collections: {e}")
        return taxii_collection_ids

    def get_collection_objects(
        self, headers: Dict[str, str], collection: str, params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Fetches objects from a specified TAXII collection using pagination.

        This function sends a GET request to retrieve objects from the given TAXII collection.
        If an access token expires (401 error), it regenerates the token and retries the request.
        It also handles pagination by checking for the "next" field in the response.

        :param headers: Dictionary containing authentication headers for the API request.
        :type headers: Dict[str, str]
        :param collection: The ID of the TAXII collection from which to fetch objects.
        :type collection: str
        :param params: Dictionary of query parameters to send with the request.
        :type params: Dict[str, Any]
        :return: A list of objects retrieved from the TAXII collection.
        :rtype: List[Dict[str, Any]]
        """
        parameters = params.copy()
        collection_objects = []
        while True:
            # Send a request to fetch objects from the collection
            resp = requests.get(
                f"{self.luminar_base_url}/externalApi/taxii/collections/{collection}/objects/",
                params=parameters,
                headers=headers,
                timeout=TIMEOUT,
            )
            # Handle the case where the access token has expired
            if resp.status_code == 401:
                self.helper.log_info(
                    f"Access token has expired, status_code={resp.status_code} "
                    f"and response={resp.text}, Regenerating token..."
                )
                access_token, _ = self.access_token()
                headers = {"Authorization": f"Bearer {access_token}"}

                continue

            # Process the response when it is successful (status code 200)
            if resp.status_code == 200:
                response_json = resp.json()
                all_objects = response_json.get("objects", [])

                collection_objects += all_objects
                # Check if there is a "next" page of objects and update the params
                if "next" in response_json:
                    parameters["next"] = response_json["next"]
                else:
                    break
            else:
                # Log an error for any unexpected status code
                self.helper.log_info(
                    f"Error occurred while fetching objects from collection {collection}: "
                    f"status_code={resp.status_code} and response={resp.text}"
                )
                break

        # Log the completion of object fetching
        self.helper.log_info(f"Fetched all objects from collection: {collection}")
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
            self.helper.log_info(f"Invalid date format: {obj_date}; {ex}")
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
                parent_stix_obj = LUMINARIOCFEEDS_X_STIX2.get(parent["type"], {})(
                    created_by_ref=self.identity["standard_id"],
                    confidence=self.confidence,
                    labels=labels,
                    description="Luminar IOC",
                    **parent,
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
                parent["created_by_ref"] = self.identity["standard_id"]
                luminar_threat_score = self.get_from_extensions(
                    "luminar_threat_score", parent
                )
                labels = (
                    [f"luminar_threat_score: {luminar_threat_score}"]
                    if luminar_threat_score
                    else []
                )
                parent_stix_obj = Incident(
                    source="Cognyte Luminar",
                    incident_type="compromise",
                    severity="high",
                    confidence=self.confidence,
                    labels=labels,
                    allow_custom=True,
                    **parent,
                )
                leaked_bundle.append(parent_stix_obj)
                custom_prop = {
                    "x_opencti_created_by_ref": self.identity["standard_id"],
                    "x_opencti_score": 100,
                }
                for c in children:
                    if c.get("type") == "malware":
                        malware_stix_obj = Malware(
                            created_by_ref=self.identity["standard_id"],
                            confidence=self.confidence,
                            labels=labels,
                            description="Luminar IOC",
                            **c,
                        )
                        mal_rel = Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", malware_stix_obj.id, parent_stix_obj.id
                            ),
                            source_ref=malware_stix_obj.id,
                            target_ref=parent_stix_obj.id,
                            relationship_type="related-to",
                            created_by_ref=self.identity["standard_id"],
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
                        user_stix_obj = UserAccount(custom_properties=custom_prop, **c)
                        user_rel = Relationship(
                            id=StixCoreRelationship.generate_id(
                                "related-to", user_stix_obj.id, parent_stix_obj.id
                            ),
                            source_ref=user_stix_obj.id,
                            target_ref=parent_stix_obj.id,
                            relationship_type="related-to",
                            created_by_ref=self.identity["standard_id"],
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
                self.helper.log_error(f"Skipping Invalid indicator: {str(obj)}")
                return
        except Exception as e:
            self.helper.log_error(f"Skipping Invalid indicator: {str(obj)} as {str(e)}")
            return
        obj["created_by_ref"] = self.identity["standard_id"]
        open_cti_indicator = Indicator(
            description=obj.get("name", "Luminar IOC"),
            confidence=(
                90 if "Known Malicious IPs" in obj.get("name", "") else self.confidence
            ),
            custom_properties={
                "x_opencti_score": (
                    90
                    if "Known Malicious IPs" in obj.get("name", "")
                    else self.x_opencti_score
                )
            },
            allow_custom=True,
            **obj,
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
                created_by_ref=self.identity["standard_id"],
                custom_properties=RELATIONSHIP_PROP,
                allow_custom=True,
            )
            bundle.extend([open_cti_indicator, ind_rel])

        if self.create_observable:
            custom_prop = {
                "x_opencti_created_by_ref": self.identity["standard_id"],
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
                    self.helper.log_error(f"Error on pattern: {pattern} and {err}")
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
                            created_by_ref=self.identity["standard_id"],
                            custom_properties=RELATIONSHIP_PROP,
                            allow_custom=True,
                        )
                        bundle.extend([open_cti_observable, obs_rel])

            else:
                self.helper.log_error(
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
            "x_opencti_created_by_ref": self.identity["standard_id"],
            "x_opencti_score": self.x_opencti_score,
            "x_opencti_confidence": self.confidence,
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
                    source_stix = LUMINARCYBERFEEDS_X_STIX2[source_rec["type"]](
                        custom_properties=custom_prop, allow_custom=True, **source_rec
                    )
                    target_stix = LUMINARCYBERFEEDS_X_STIX2[target_rec["type"]](
                        custom_properties=custom_prop, allow_custom=True, **target_rec
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
                        created_by_ref=self.identity["standard_id"],
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
                    ref_obj["description"] = self.get_description(ref_obj)
                    ref_stix = LUMINARCYBERFEEDS_X_STIX2[ref_type](
                        custom_properties=custom_prop, allow_custom=True, **ref_obj
                    )
                    object_refs_stix.append(ref_stix.id)
                    cyberfeeds_bundle.append(ref_stix)
                elif ref_type == "indicator" and ref_obj:
                    self.process_opencti_indicator(
                        ref_obj, None, cyberfeeds_bundle, object_refs_stix, True
                    )

            if object_refs_stix:
                rep["object_refs"] = object_refs_stix
                cyberfeeds_bundle.append(
                    Report(
                        created_by_ref=self.identity["standard_id"],
                        confidence=self.confidence,
                        custom_properties={"x_opencti_score": self.x_opencti_score},
                        allow_custom=True,
                        **rep,
                    )
                )
        return cyberfeeds_bundle

    def can_run_now(self, next_run: str, days: int = 1) -> bool:
        """
        Returns True if current UTC time is greater than next_run + days.
        Otherwise, returns False.

        :param next_run: A string in format "%Y-%m-%dT%H:%M:%S.%fZ"
        :param days: Number of days to add to next_run
        :return: Boolean
        """
        try:
            # Parse the next_run time string into a datetime object
            next_run_dt = datetime.strptime(next_run, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=timezone.utc
            )

            # Add the specified number of days
            threshold_time = next_run_dt + timedelta(days=days)
            # Get the current UTC time
            current_time = datetime.now(timezone.utc)
            # Compare times
            if threshold_time > current_time:
                self.helper.log_info(
                    f"The connector is scheduled to run after {threshold_time} (UTC)"
                )
            return current_time > threshold_time
        except ValueError as e:
            print(f"Error parsing datetime: {e}")
            return False

    def run(self):
        """Runs the main process."""
        try:
            current_state = self.helper.get_state()
            last_run = None
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

            if not last_run or self.can_run_now(last_run, self.duration_interval):

                self.helper.log_info("Connecting to Cognyte Luminar...")
                access_token, message = self.access_token()
                if not access_token:
                    self.helper.log_error(f"Failed to get access token: {message}")
                    return

                headers = {"Authorization": f"Bearer {access_token}"}
                taxii_collection = self.get_taxi_collections(headers)
                if not taxii_collection:
                    return

                next_checkpoint = self.get_timestamp()
                from_date = last_run or self.initial_fetch_date + "T00:00:00.000000Z"

                params = {"limit": 9999}
                params["added_after"] = from_date
                self.helper.log_info(f"Fetching Luminar data from {from_date}")

                ioc_records = self.get_collection_objects(
                    headers, taxii_collection["iocs"], params
                )
                self.helper.log_info(f"IOC records fetched: {len(ioc_records)}")

                leaked_records = self.get_collection_objects(
                    headers, taxii_collection["leakedrecords"], params
                )
                self.helper.log_info(f"Leaked records fetched: {len(leaked_records)}")

                cyberfeeds_records = self.get_collection_objects(
                    headers, taxii_collection["cyberfeeds"], params
                )
                self.helper.log_info(
                    f"cyberfeeds records fetched: {len(cyberfeeds_records)}"
                )

                ioc_processed_records = self.process_iocs(from_date, ioc_records)
                leaked_processed_records = self.process_leaked(
                    from_date, leaked_records
                )
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
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, "luminar"
                    )
                    self.helper.send_stix2_bundle(
                        bundle=all_bundle, update=True, work_id=work_id
                    )
                else:
                    self.helper.log_info("No new data to import!")

                self.helper.set_state({"last_run": next_checkpoint})
                self.helper.log_info(
                    f"Saving checkpoint for next run: {next_checkpoint}"
                )

        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as error:
            self.helper.log_error(str(error))

        if self.helper.connect_run_and_terminate:
            self.helper.log_info("Connector stop")
            self.helper.force_ping()
            sys.exit(0)

        time.sleep(60)


if __name__ == "__main__":
    try:
        luminar = LuminarManager()
        luminar.run()

    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
