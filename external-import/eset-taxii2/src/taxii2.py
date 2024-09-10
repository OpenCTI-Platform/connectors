"""ESET Threat Intelligence TAXII2 connector. """

import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import taxii2client.v21 as tx21
import yaml
from pycti import OpenCTIConnectorHelper, StixCyberObservableTypes, get_config_variable
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError
from stix2.confidence.scales import value_to_none_low_medium_high
from taxii2client.common import _ensure_datetime_to_string
from taxii2client.exceptions import TAXIIServiceException

from client import HTTPConnectionWithTAXIIHeaders


class Taxii2Connector:
    """Connector object"""

    def __init__(self):
        """Read in config variables"""

        config_file_path = os.path.dirname(os.path.abspath(__file__))
        config_file_path += "/config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
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
        server_url = get_config_variable(
            "TAXII2_DISCOVERY_URL", ["taxii2", "discovery_url"], config
        )

        self.server = tx21.Server(
            server_url,
            conn=HTTPConnectionWithTAXIIHeaders(
                auth=HTTPBasicAuth(username, password.encode())
            ),
        )

        self.collections = [
            x.strip()
            for x in get_config_variable(
                "TAXII2_COLLECTIONS", ["taxii2", "collections"], config
            )
            .strip()
            .split(",")
            if x
        ]
        self.initial_history = get_config_variable(
            "TAXII2_INITIAL_HISTORY", ["taxii2", "initial_history"], config, True
        )
        self.per_request = get_config_variable(
            "TAXII2_PER_REQUEST", ["taxii2", "per_request"], config, True, default=1000
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

    def get_interval(self):
        """Converts interval hours to seconds"""
        return int(self.interval) * 3600

    @property
    def first_run(self):
        """Checks if connector has run before"""
        current_state = self.helper.get_state()
        return current_state is None or "last_run" not in current_state

    def _iter_collections(self):
        """Iterates collections. Yields tuple API root, collection."""
        for collection in self.collections:
            try:
                # Collection tile may contain '.'
                root_uid, uid_or_title = collection.split(".", 1)

                for root in self._get_roots(root_uid):
                    try:
                        for coll in self._get_collections(root, uid_or_title):
                            yield root, coll
                    except TAXIIServiceException:
                        self.helper.log_error(
                            f"Error searching for collection {uid_or_title} in API Root {root.title}"
                        )

            except (TAXIIServiceException, HTTPError) as err:
                self.helper.log_error(
                    f"Error connecting to TAXII server '{self.server.url}'"
                )
                self.helper.log_error(err)
                continue

    # noinspection PyMethodMayBeStatic
    def _get_cursor(self, state, root_title, collection_title):
        """Returns the latest position, from which connector read data."""
        cursors = state.get(root_title, dict()) if state else dict()
        return cursors.get(collection_title)

    # noinspection PyMethodMayBeStatic
    def _update_cursor(self, state, root_title, collection_title, cursor):
        """Updates position for collection."""
        if state is None:
            state = dict()

        cursors = state.get(root_title)

        if cursors is None:
            state[root_title] = dict()

        state[root_title][collection_title] = cursor
        return state

    def run(self):
        """Run connector on a schedule"""
        while True:
            self.server.refresh()

            now = datetime.now()
            state = self.helper.get_state()

            if self.first_run:
                self.helper.log_info("Connector has never run")
            else:
                self.helper.log_info(
                    "Connector last run: "
                    + datetime.utcfromtimestamp(state["last_run"]).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

            for root, collection in self._iter_collections():
                title = None

                try:
                    title = collection.title

                    # Get the last position for this collection.
                    cursor = self._get_cursor(state, root.title, collection.title)

                    if not cursor and self.initial_history is not None:
                        cursor = _ensure_datetime_to_string(
                            now - timedelta(hours=self.initial_history)
                        )
                        # Remember the initial position in case the collection is emtpy.
                        state = self._update_cursor(
                            state, root.title, collection.title, cursor
                        )

                    cursor = self.poll(collection, cursor)

                    if cursor is None:
                        # No new objects in the collection since the last poll, advance cursor
                        cursor = _ensure_datetime_to_string(now)

                    state = self._update_cursor(
                        state, root.title, collection.title, cursor
                    )

                except TAXIIServiceException as err:
                    msg = (
                        f"Error trying to poll collection {title} "
                        f"in API Root {root.title}. Skipping"
                    )
                    self.helper.log_error(msg)
                    self.helper.log_error(err)

            self.helper.log_info(
                f"Run Complete. Sleeping until next run in " f"{self.interval} hours"
            )

            if state is None:
                state = dict()

            state["last_run"] = int(now.timestamp())

            self.helper.set_state(state)

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(self.get_interval())

    def poll(self, collection, cursor):
        """
        Polls a specified collection in a specified API root

        Args:
            collection (taxii2client.v21.Collection): The Collection to poll
            cursor str: The latest positions where to start polling
        """
        filters = dict(limit=self.per_request)

        if cursor:
            filters["added_after"] = cursor

        self.helper.log_info(
            f"Polling Collection '{collection.title}', " f"added after: {cursor}"
        )

        # Initial request
        response = collection.get_objects(**filters)
        taxii_added_last = None

        if not response.get("objects"):
            self.helper.log_info("No objects found in request.")
        else:

            work_id = self.helper.api.work.initiate_work(
                self.helper.connector_id,
                f"{collection.title} @ {cursor}" if cursor else collection.title,
            )

            if "spec_version" in response:
                version = response["spec_version"]
            else:
                version = response["objects"][0]["spec_version"]

            objects = []
            while True:
                taxii_added_last = response.taxii_added_last
                objects.extend(response["objects"])

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
            self.send_to_server(new_bundle, work_id)

        return taxii_added_last

    def _process_objects(self, stix_bundle: Dict) -> Dict:
        observable_objects: Dict[str, Dict] = {}
        observable_refs_confidence: Dict[str, int] = {}

        for obj in stix_bundle["objects"]:
            # Add a custom label
            labels: Optional[List[str]] = obj.get("labels")

            if self.add_custom_label:
                labels = labels or []
                labels.append(self.custom_label)
                obj["labels"] = labels

            if "confidence" in obj:
                set_custom_properties(obj, confidence=obj["confidence"])

            object_type = obj["type"]

            if object_type == "indicator":
                match = re.search(r"\[(.*?):.*'(.*?)\'\]", obj["pattern"])
                if match is not None:
                    if match[1] == "ipv4-addr":
                        obj["x_opencti_main_observable_type"] = "IPv4-Addr"
                    elif match[1] == "ipv6-addr":
                        obj["x_opencti_main_observable_type"] = "IPv6-Addr"
                    elif match[1] == "file":
                        obj["x_opencti_main_observable_type"] = "StixFile"
                    elif match[1] == "domain-name":
                        obj["x_opencti_main_observable_type"] = "Domain-Name"
                    elif match[1] == "url":
                        obj["x_opencti_main_observable_type"] = "Url"
                    elif match[1] == "email-addr":
                        obj["x_opencti_main_observable_type"] = "Email-Addr"
                # Force name to be derived from a pattern
                if self.force_pattern_as_name:
                    if " AND " in obj["pattern"] or " OR " in obj["pattern"]:
                        obj["name"] = self.force_multiple_pattern_name
                    else:
                        if match is not None:
                            obj["name"] = match[2]

                obj["x_opencti_create_observables"] = self.create_observables

            elif StixCyberObservableTypes.has_value(object_type):
                obj["x_opencti_create_indicators"] = self.create_indicators
                object_id = obj["id"]

                if object_id in observable_refs_confidence:
                    set_custom_properties(obj, observable_refs_confidence[object_id])
                    del observable_refs_confidence[object_id]
                else:
                    observable_objects[object_id] = obj

            elif object_type == "observed-data":
                confidence = obj.get("confidence")
                if "objects" in obj:
                    for observable in obj["objects"].values():
                        if not StixCyberObservableTypes.has_value(observable["type"]):
                            continue
                        set_custom_properties(observable, confidence)

                if "object_refs" in obj:
                    for observable_ref in obj["object_refs"]:
                        if observable_ref in observable_objects:
                            set_custom_properties(
                                observable_objects[observable_ref],
                                confidence=confidence,
                            )
                            del observable_objects[observable_ref]
                        else:
                            observable_refs_confidence[observable_ref] = confidence

        return stix_bundle

    def send_to_server(self, bundle, work_id):
        """
        Sends a STIX2 bundle to OpenCTI Server
        Args:
            bundle (list(dict)): STIX2 bundle represented as a list of dicts
            work_id (str): OpenCTI work id
        """
        self.helper.log_info(
            f"Sending Bundle to server with '{len(bundle.get('objects', []))}' objects"
        )

        try:
            bundle_json = json.dumps(self._process_objects(bundle))

            self.helper.log_debug(f"Bundle data: {bundle_json}")

            bundles = self.helper.send_stix2_bundle(
                bundle_json,
                update=self.update_existing_data,
                work_id=work_id,
            )

            self.helper.log_debug(f"Sent bundles: {bundles}")

        except Exception as e:
            self.helper.log_error(str(e))

    # noinspection PyMethodMayBeStatic
    def _get_collections(self, root, uid_or_title):
        """
        Yields collection objects matching `uid_or_title`, given an API Root and a collection name
        Args:
            root (taxii2.v21.ApiRoot): The API Root to search through
            uid_or_title (str): The Name or UUID of the target Collections
        Returns:
            The taxii2.v21.Collection object with the name `coll_title`
        """
        if uid_or_title != "*":
            for collection in root.collections:
                if collection.title == uid_or_title or collection.id == uid_or_title:
                    yield collection
                    return

            raise TAXIIServiceException(
                f"Collection {uid_or_title} does not exist in API root {root.title}"
            )

        # Yield all collections from root
        yield from root.collections

    def _get_roots(self, root_path):
        """
        Yields API root objects matching `root_path`.
        Args:
            root_path (str): the path of the API root in the URL
        Returns:
            The taxii2.v21.ApiRoot object with the name `root_path`

        """
        for root in self.server.api_roots:
            if root_path == "*" or root.url.split("/")[-2] == root_path:
                # For some reason, taxii2client.Server does not pass custom connection instance
                # to API roots
                root._conn = HTTPConnectionWithTAXIIHeaders(
                    auth=self.server._conn.session.auth,
                    cert=self.server._conn.session.cert,
                )

                yield root

                if root_path != "*":
                    break
        else:
            if root_path != "*":
                raise TAXIIServiceException(
                    f"Api Root {root_path} does not exist in the TAXII server"
                )


def stix_confidence_to_opencti_score(confidence: Optional[int]) -> int:
    if confidence is not None:
        value = value_to_none_low_medium_high(confidence)

        if value == "Low":
            return 50
        if value == "Medium":
            return 70
        if value == "High":
            return 95

    # Default score
    return 50


def set_custom_properties(obj: Dict, confidence: Optional[int]) -> None:
    props = obj.get("custom_properties")

    if props is None:
        props = {}
        obj["custom_properties"] = props
    props["x_opencti_score"] = stix_confidence_to_opencti_score(confidence)


if __name__ == "__main__":
    try:
        taxii2Connector = Taxii2Connector()
        taxii2Connector.run()
    except Exception as e:
        raise e
