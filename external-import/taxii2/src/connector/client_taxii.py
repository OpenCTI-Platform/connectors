import taxii2client.v20 as tx20
import taxii2client.v21 as tx21
from requests.auth import AuthBase, HTTPBasicAuth
from taxii2client.common import TokenAuth
from taxii2client.exceptions import TAXIIServiceException


class ApiKeyAuth(AuthBase):
    """
    Used to auth against Taxii servers
    """

    def __init__(self, api_key, value):
        self.api_key = api_key
        self.value = value

    def __call__(self, r):
        r.headers[self.api_key] = f"{self.value}"
        return r


class Taxii2:
    """
    Functions specifically used to connect to Taxii servers
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config

        if self.config.use_token:
            auth = TokenAuth(self.config.token)
        elif self.config.use_apikey:
            auth = ApiKeyAuth(self.config.apikey_key, self.config.apikey_value)
        else:
            auth = HTTPBasicAuth(self.config.username, self.config.password)
        if self.config.taxii2v21:
            self.config.server = tx21.Server(
                self.config.discovery_url,
                auth=auth,
                verify=self.config.verify_ssl,
                cert=self.config.cert_path,
            )
        else:
            self.config.server = tx20.Server(
                self.config.discovery_url,
                auth=auth,
                verify=self.config.verify_ssl,
                cert=self.config.cert_path,
            )

        self.filters = {}
        if self.config.enable_url_query_limit and self.config.taxii2v21:
            self.filters["limit"] = self.config.url_query_limit

    def _get_root(self, root_path):
        """
        Returns an APi Root object, given a Server and an API Root path
        """
        for root in self.config.server.api_roots:
            if root.url.split("/")[-2] == root_path:
                return root
        msg = f"Api Root {root_path} does not exist in the TAXII server"
        raise TAXIIServiceException(msg)

    def _get_collection(self, root, coll_title):
        """
        Returns a Collection object, given an API Root and a collection name
        """
        for coll in root.collections:
            if coll.title == coll_title:
                return coll
        msg = f"Collection {coll_title} does not exist in API root {root.title}"
        raise TAXIIServiceException(msg)

    def poll_all_roots(self, coll_title):
        """
        Polls all API roots for the specified collections
        """
        self.helper.log_info("Polling all API Roots")
        stix_objects = []
        for root in self.config.server.api_roots:
            if coll_title == "*":
                obj = self.poll_entire_root(root)
                if len(obj) > 0:
                    stix_objects.extend(iter(obj))
            else:
                try:
                    coll = self._get_collection(root, coll_title)
                except TAXIIServiceException:
                    self.helper.log_error(
                        f"Error searching for  collection {coll_title} in API Root {root.title}"
                    )
                    return
                try:
                    obj2 = self.poll(coll)
                    if len(obj2) > 0:
                        stix_objects.extend(iter(obj2))
                except TAXIIServiceException as err:
                    msg = (
                        f"Error trying to poll Collection {coll_title} "
                        f"in API Root {root.title}. Skipping"
                    )
                    self.helper.log_error(msg)
                    self.helper.log_error(err)
        return stix_objects

    def poll_entire_root(self, root):
        """
        Polls all Collections in a given API Root
        """
        self.helper.log_info(f"Polling entire API root {root.title}")
        stix_objects = []
        for coll in root.collections:
            try:
                obj = self.poll(coll)
                if len(obj) > 0:
                    stix_objects.extend(iter(obj))
            except TAXIIServiceException as err:
                msg = (
                    f"Error trying to poll Collection {coll.title} "
                    f"in API Root {root.title}. Skipping"
                )
                self.helper.log_error(msg)
                self.helper.log_error(err)
        return stix_objects

    def process_response(self, objects, response):
        # This function is required to concat the paginated responses
        if "objects" in response:
            for object in response["objects"]:
                objects.append(object)
        return objects

    def get_objects(self, collection):
        try:
            return collection.get_objects(**self.filters)
        except TAXIIServiceException as err:
            msg = f"Error trying to get objects from Collection {collection.title}"
            self.helper.log_error(msg)
            self.helper.log_error(err)

    def get_manifest(self, collection, last_obj):
        try:
            return collection.get_manifest(id=last_obj["id"])
        except TAXIIServiceException as err:
            msg = f"Error trying to get manifest from Collection {collection.title}"
            self.helper.log_error(msg)
            self.helper.log_error(err)

    def poll(self, collection):
        """
        Polls a specified collection in a specified API root
        """
        objects = []
        self.helper.log_info(f"Polling Collection {collection.title}")
        response = self.get_objects(collection)
        if (
            response is not None
            and "objects" in response
            and len(response["objects"]) > 0
        ):
            first_object = response["objects"][0]
            if "spec_version" in response:
                self.version = response["spec_version"]
            elif "spec_version" in first_object:
                self.version = first_object["spec_version"]
            else:
                self.helper.log_info("No spec_version found, assuming TAXII 2.0")
                self.version = "2.0"  # Default to TAXII 2.0 if nothing found
            # Taxii 2.0 doesn't support using next, using manifest lookup instead
            if self.version == "2.0":
                while True:
                    objects = self.process_response(objects, response)
                    # Get the manifest for the last object
                    last_obj = response["objects"][-1]
                    manifest = self.get_manifest(collection, last_obj)
                    # Check manifest size
                    if "objects" in manifest and len(manifest["objects"]) > 0:
                        date_added = manifest["objects"][0]["date_added"]
                        self.filters["added_after"] = date_added
                        # Get the next set of objects
                        response = self.get_objects(collection)
                        if len(response["objects"]) == 0:
                            break
                    else:
                        self.helper.log_info("No manifest found. Stopping pagination.")
                        break
            else:
                # Assuming newer versions will support next
                while True:
                    objects = self.process_response(objects, response)
                    if "more" not in response or response["more"] != True:
                        # "more" doesn't exist or is not True, exit the loop
                        break
                    if "next" in response:
                        self.filters.pop("added_after", None)
                        self.filters["next"] = response["next"]
                        response = self.get_objects(collection)
        return objects
