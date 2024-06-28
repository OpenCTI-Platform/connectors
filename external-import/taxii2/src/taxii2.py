"""Generic TAXII2 connector. """

import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict

import taxii2client.v20 as tx20
import taxii2client.v21 as tx21
import yaml
from pycti import OpenCTIConnectorHelper, StixCyberObservableTypes, get_config_variable
from requests.auth import AuthBase, HTTPBasicAuth
from requests.exceptions import HTTPError
from taxii2client.common import TokenAuth
from taxii2client.exceptions import TAXIIServiceException


class ApiKeyAuth(AuthBase):
    def __init__(self, api_key, value):
        self.api_key = api_key
        self.value = value

    def __call__(self, r):
        r.headers[self.api_key] = "{}".format(self.value)
        return r


class Taxii2Connector:
    """Connector object"""

    def __init__(self):
        """Read in config variables"""

        config_file_path = os.path.dirname(os.path.abspath(__file__))
        config_file_path += "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        username = get_config_variable(
            "TAXII2_USERNAME", ["taxii2", "username"], config
        )
        password = get_config_variable(
            "TAXII2_PASSWORD", ["taxii2", "password"], config
        )
        use_token = get_config_variable(
            "TAXII2_USE_TOKEN", ["taxii2", "use_token"], config, default=False
        )
        token = get_config_variable("TAXII2_TOKEN", ["taxii2", "token"], config)
        use_apikey = get_config_variable(
            "TAXII2_USE_APIKEY", ["taxii2", "use_apikey"], config, default=False
        )
        apikey_key = get_config_variable(
            "TAXII2_APIKEY_KEY", ["taxii2", "apikey_key"], config
        )
        apikey_value = get_config_variable(
            "TAXII2_APIKEY_VALUE", ["taxii2", "apikey_value"], config
        )
        server_url = get_config_variable(
            "TAXII2_DISCOVERY_URL", ["taxii2", "discovery_url"], config
        )
        cert_path = get_config_variable(
            "TAXII2_CERT_PATH", ["taxii2", "cert_path"], config
        )
        self.verify_ssl = get_config_variable(
            "TAXII2_VERIFY_SSL", ["taxii2", "verify_ssl"], config, default=True
        )
        # if V21 flag set to true
        self.taxii2v21 = get_config_variable(
            "TAXII2_V21", ["taxii2", "v2.1"], config, default=True
        )
        if use_token:
            auth = TokenAuth(token)
        elif use_apikey:
            auth = ApiKeyAuth(apikey_key, apikey_value)
        else:
            auth = HTTPBasicAuth(username, password)
        if self.taxii2v21:
            self.server = tx21.Server(
                server_url,
                auth=auth,
                verify=self.verify_ssl,
                cert=cert_path,
            )
        else:
            self.server = tx20.Server(
                server_url,
                auth=auth,
                verify=self.verify_ssl,
                cert=cert_path,
            )
        self.collections = get_config_variable(
            "TAXII2_COLLECTIONS", ["taxii2", "collections"], config
        ).split(",")
        self.initial_history = get_config_variable(
            "TAXII2_INITIAL_HISTORY", ["taxii2", "initial_history"], config, True
        )
        self.per_request = get_config_variable(
            "TAXII2_PER_REQUEST", ["taxii2", "per_request"], config, True
        )
        self.interval = get_config_variable(
            "TAXII2_INTERVAL", ["taxii2", "interval"], config, True, 1
        )
        self.create_indicators = get_config_variable(
            "TAXII2_CREATE_INDICATORS",
            ["taxii2", "create_indicators"],
            config,
            False,
            True,
        )
        self.create_observables = get_config_variable(
            "TAXII2_CREATE_OBSERVABLES",
            ["taxii2", "create_observables"],
            config,
            False,
            True,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.add_custom_label = get_config_variable(
            "TAXII2_ADD_CUSTOM_LABEL",
            ["taxii2", "add_custom_label"],
            config,
            default=False,
        )
        self.custom_label = get_config_variable(
            "TAXII2_CUSTOM_LABEL", ["taxii2", "custom_label"], config
        )
        self.force_pattern_as_name = get_config_variable(
            "TAXII2_FORCE_PATTERN_AS_NAME",
            ["taxii2", "force_pattern_as_name"],
            config,
            default=False,
        )
        self.force_multiple_pattern_name = get_config_variable(
            "TAXII2_FORCE_MULTIPLE_PATTERN_NAME",
            ["taxii2", "force_multiple_pattern_name"],
            config,
        )
        self.stix_custom_property_to_label = get_config_variable(
            "TAXII2_STIX_CUSTOM_PROPERTY_TO_LABEL",
            ["taxii2", "stix_custom_property_to_label"],
            config,
            default=False,
        )
        self.stix_custom_property = get_config_variable(
            "TAXII2_STIX_CUSTOM_PROPERTY",
            ["taxii2", "stix_custom_property"],
            config,
        )

    @staticmethod
    def _init_collection_table(colls):
        """
        Creates a table of string:Set where the key is the API root
        and the value is the list of Collections to read

        Args:
            colls (str): a comma delimited list of API
                         roots and Collections to Poll
        Returns:
            A dictionary with [str, Set], where the Key is the API root
            and the value is the list of Collections to be polled
        """
        table = {}
        for col in colls.split(","):
            root, coll = col.split(".")
            if root in table:
                table[root].add(coll)
            else:
                table[root] = {coll}

        return table

    def get_interval(self):
        """Converts interval hours to seconds"""
        return int(self.interval) * 3600

    @property
    def first_run(self):
        """Checks if connector has run before"""
        current_state = self.helper.get_state()
        return current_state is None or "last_run" not in current_state

    def run(self):
        """Run connector on a schedule"""
        while True:
            self.server.refresh()
            timestamp = int(time.time())
            if self.first_run:
                self.helper.log_info("Connector has never run")
            else:
                last_run = datetime.fromtimestamp(
                    self.helper.get_state()["last_run"], tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S")
                self.helper.log_info("Connector last run: " + last_run)

            for collection in self.collections:
                try:
                    root_path, coll_title = collection.split(".")
                    if root_path == "*":
                        self.poll_all_roots(coll_title)
                    elif coll_title == "*":
                        root = self._get_root(root_path)
                        self.poll_entire_root(root)
                    else:
                        root = self._get_root(root_path)
                        coll = self._get_collection(root, coll_title)
                        self.poll(coll)
                except (TAXIIServiceException, HTTPError) as err:
                    self.helper.log_error("Error connecting to TAXII server")
                    self.helper.log_error(err)
                    continue
            self.helper.log_info(
                f"Run Complete. Sleeping until next run in " f"{self.interval} hours"
            )
            self.helper.set_state({"last_run": timestamp})

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(self.get_interval())

    def poll_all_roots(self, coll_title):
        """
        Polls all API roots for the specified collections
        Args:
            coll_title (str): The Name of a Collection
        """
        self.helper.log_info("Polling all API Roots")
        for root in self.server.api_roots:
            if coll_title == "*":
                self.poll_entire_root(root)
            else:
                try:
                    coll = self._get_collection(root, coll_title)
                except TAXIIServiceException:
                    self.helper.log_error(
                        f"Error searching for  collection {coll_title} in API Root {root.title}"
                    )
                    return
                try:
                    self.poll(coll)
                except TAXIIServiceException as err:
                    msg = (
                        f"Error trying to poll Collection {coll_title} "
                        f"in API Root {root.title}. Skipping"
                    )
                    self.helper.log_error(msg)
                    self.helper.log_error(err)

    def poll_entire_root(self, root):
        """
        Polls all Collections in a given API Root
        Args:
            root (taxii2client.v2*.ApiRoot: Api Root to poll
        """
        self.helper.log_info(f"Polling entire API root {root.title}")

        for coll in root.collections:
            try:
                self.poll(coll)
            except TAXIIServiceException as err:
                msg = (
                    f"Error trying to poll Collection {coll.title} "
                    f"in API Root {root.title}. Skipping"
                )
                self.helper.log_error(msg)
                self.helper.log_error(err)

    def poll(self, collection):
        """
        Polls a specified collection in a specified API root
        Args:
            collection (taxii2client.v2*.Collection: THe Collection to poll
        """

        def process_response(objects, response, version):
            # Function to process data from taxii servers
            for object in response["objects"]:
                # If taxii feed is v2.0 append pattern_type if it does not exist
                if version == "2.0" and "pattern_type" not in object:
                    object["pattern_type"] = "stix"
                # Add a custom label
                new_labels = []
                if "labels" in object:
                    new_labels = object["labels"]
                if self.add_custom_label == True:
                    new_labels.append(self.custom_label)
                    object["labels"] = new_labels
                if (
                    self.stix_custom_property_to_label == True
                    and self.stix_custom_property in object
                ):
                    new_labels.append(object[self.stix_custom_property])
                    object["labels"] = new_labels
                # Enumerate main observable type
                if object["type"] == "indicator":
                    match = re.search(r"\[(.*?):.*'(.*?)\'\]", object["pattern"])
                    if match != None:
                        if match[1] == "ipv4-addr":
                            object["x_opencti_main_observable_type"] = "IPv4-Addr"
                        elif match[1] == "ipv6-addr":
                            object["x_opencti_main_observable_type"] = "IPv6-Addr"
                        elif match[1] == "file":
                            object["x_opencti_main_observable_type"] = "StixFile"
                        elif match[1] == "domain-name":
                            object["x_opencti_main_observable_type"] = "Domain-Name"
                        elif match[1] == "url":
                            object["x_opencti_main_observable_type"] = "Url"
                        elif match[1] == "email-addr":
                            object["x_opencti_main_observable_type"] = "Email-Addr"
                    # Force name to be derived from pattern
                    if self.force_pattern_as_name == True:
                        if " AND " in object["pattern"] or " OR " in object["pattern"]:
                            object["name"] = self.force_multiple_pattern_name
                        else:
                            if match != None:
                                object["name"] = match[2]
                objects.append(object)
            return objects

        filters = {}
        if self.first_run:
            lookback = self.initial_history or None
        else:
            lookback = self.interval
        if lookback:
            added_after = datetime.now() - timedelta(hours=lookback)
            filters["added_after"] = added_after
        self.helper.log_info(f"Polling Collection {collection.title}")

        # Initial request
        response = collection.get_objects(**filters)
        more = None
        objects = []
        if "objects" in response and len(response["objects"]) > 0:
            if "spec_version" in response:
                version = response["spec_version"]
            else:
                version = response["objects"][0]["spec_version"]
            # Taxii 2.0 doesn't support using next, using manifest lookup instead
            if version == "2.0":
                while more != False:
                    objects = process_response(objects, response, version)
                    # Get the manifest for the last object
                    last_obj = response["objects"][-1]
                    manifest = {"objects": []}
                    try:
                        manifest = collection.get_manifest(id=last_obj["id"])
                    except HTTPError as e:
                        if e.response.status_code == 404:
                            # Handle the 404 error gracefully
                            print(
                                f"The collection '{last_obj['id']}' does not exist or is not accessible."
                            )
                        else:
                            # Handle other HTTP errors if necessary
                            print(
                                f"HTTP Error: {e.response.status_code} - {e.response.reason}"
                            )
                    # Check manifest size
                    if len(manifest["objects"]) > 0:
                        date_added = manifest["objects"][0]["date_added"]
                        filters["added_after"] = date_added
                        # Get the next set of objects
                        response = collection.get_objects(**filters)
                        more = "objects" in response and len(response["objects"]) > 0
                    else:
                        self.helper.log_info("No manifest found. Stopping pagination.")
                        more = False
            else:
                # Assuming newer versions will support next
                while True:
                    objects = process_response(objects, response, version)

                    # Check if "more" exists in response and its value is True
                    if "more" in response and response["more"] == True:
                        filters["next"] = response["next"]
                        response = collection.get_objects(**filters)
                    else:
                        # "more" doesn't exist or is not True, exit the loop
                        break

            # Create bundle
            new_bundle = {
                "type": "bundle",
                "id": f"bundle--{str(uuid.uuid4())}",
                "spec_version": version,
                "objects": objects,
            }
            self.send_to_server(new_bundle, collection)
        else:
            self.helper.log_info("No objects found in request.")

    def _process_objects(self, stix_bundle: Dict) -> Dict:
        for obj in stix_bundle["objects"]:
            object_type = obj["type"]
            if object_type == "indicator":
                obj["x_opencti_create_observables"] = self.create_observables
            elif StixCyberObservableTypes.has_value(object_type):
                obj["x_opencti_create_indicators"] = self.create_indicators
        return stix_bundle

    def send_to_server(self, bundle, collection):
        """
        Sends a STIX2 bundle to OpenCTI Server
        Args:
            bundle (list(dict)): STIX2 bundle represented as a list of dicts
        """

        self.helper.log_info(
            f"Sending Bundle to server with '{len(bundle.get('objects', []))}' objects"
        )

        # Create work id
        now = datetime.now(timezone.utc)
        friendly_name = (
            f"{self.helper.connect_name} - {collection.title} run @ "
            + now.strftime("%Y-%m-%d %H:%M:%S")
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        try:
            self.helper.send_stix2_bundle(
                json.dumps(self._process_objects(bundle)),
                update=self.update_existing_data,
                work_id=work_id,
            )

        except Exception as e:
            self.helper.log_error(str(e))

    def _get_collection(self, root, coll_title):
        """
        Returns a Collection object, given an API Root and a collection name
        Args:
            root (taxii2.v2*.ApiRoot): The API Root to search through
            coll_title (str): The Name of the target Collections
        Returns:
            The taxii2.v2*.Collection object with the name `coll_title`

        """
        for coll in root.collections:
            if coll.title == coll_title:
                return coll
        msg = f"Collection {coll_title} does not exist in API root {root.title}"
        raise TAXIIServiceException(msg)

    def _get_root(self, root_path):
        """
        Returns an APi Root object, given a Server and an API Root path
        Args:
            Server (taxii2.v2*.Server): The TAXII Server to search for
            root_path (str): the path of the API root in the URL
        Returns:
            The taxii2.v2*.Collection object with the name `coll_title`

        """
        for root in self.server.api_roots:
            if root.url.split("/")[-2] == root_path:
                return root
        msg = f"Api Root {root_path} does not exist in the TAXII server"
        raise TAXIIServiceException(msg)


if __name__ == "__main__":
    try:
        taxii2Connector = Taxii2Connector()
        taxii2Connector.run()
    except Exception as e:
        raise e
