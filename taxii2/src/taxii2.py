"""Generic TAXII2 connector. """

import os
import time
import json
from datetime import datetime, timedelta
import yaml
from requests.exceptions import HTTPError
import taxii2client.v20 as tx20
import taxii2client.v21 as tx21
from taxii2client.exceptions import TAXIIServiceException
from pycti import OpenCTIConnectorHelper, get_config_variable


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
        server_url = get_config_variable(
            "TAXII2_DISCOVERY_URL", ["taxii2", "discovery_url"], config
        )
        self.verify_ssl = get_config_variable(
            "VERIFY_SSL", ["taxii2", "verify_ssl"], config, default=True
        )

        # if V21 flag set to true
        if get_config_variable("TAXII2_V21", ["taxii2", "v2.1"], config, default=True):
            self.server = tx21.Server(
                server_url, user=username, password=password, verify=self.verify_ssl
            )
        else:
            self.server = tx20.Server(
                server_url, user=username, password=password, verify=self.verify_ssl
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

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
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
                last_run = None
                self.helper.log_info("Connector has never run")
            else:
                last_run = datetime.utcfromtimestamp(
                    self.helper.get_state()["last_run"]
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
                except TAXIIServiceException as err:
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
            colllection (taxii2client.v2*.Collection: THe Collection to poll
        """

        filters = {}
        if self.first_run:
            lookback = self.initial_history or None
        else:
            lookback = self.interval
        if lookback:
            added_after = datetime.now() - timedelta(hours=lookback)
            filters["added_after"] = added_after
        self.helper.log_info(f"Polling Collection {collection.title}")
        self.send_to_server(collection.get_objects(**filters))

    def send_to_server(self, bundle):
        """
        Sends a STIX2 bundle to OpenCTI Server
        Args:
            bundle (list(dict)): STIX2 bundle represented as a list of dicts
        """

        self.helper.log_info(
            f"Sending Bundle to server with " f'{len(bundle["objects"])} objects'
        )
        try:
            self.helper.send_stix2_bundle(
                json.dumps(bundle),
                update=self.update_existing_data,
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
        CONNECTOR = Taxii2Connector()
        CONNECTOR.run()
    except Exception as e:
        raise (e)
