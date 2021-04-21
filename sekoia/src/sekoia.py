import base64
import json
import os
import time
from datetime import datetime, timedelta
from posixpath import join as urljoin
from typing import Any, Iterable, List, Set, Dict

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from requests import RequestException


class Sekoia(object):

    limit = 20

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self._cache = {}
        # Extra config
        self.base_url = self.get_config("base_url", config, "https://api.sekoia.io")
        self.collection = self.get_config(
            "collection", config, "d6092c37-d8d7-45c3-8aff-c4dc26030608"
        )

        self.helper.log_info("Setting up api key")
        self.api_key = self.get_config("api_key", config)
        if not self.api_key:
            self.helper.log_error("API key is Missing")
            raise ValueError("API key is Missing")

        self._load_data_sets()

    def run(self):
        self.helper.log_info("Starting SEKOIA.IO connector")
        state = self.helper.get_state() or {}
        cursor = state.get("last_cursor", self.generate_first_cursor())
        self.helper.log_info(f"Starting with {cursor}")
        while True:
            try:
                cursor = self._run(cursor)
                self.helper.log_info(f"Cursor updated to {cursor}")
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as ex:
                # In case of error try to get the last updated cursor
                # since `_run` updates it after every successful request
                state = self.helper.get_state() or {}
                cursor = state.get("last_cursor", cursor)
                self.helper.log_error(str(ex))
            time.sleep(60)

    @staticmethod
    def get_config(name: str, config, default: Any = None):
        env_name = f"SEKOIA_{name.upper()}"
        result = get_config_variable(env_name, ["sekoia", name], config)
        return result or default

    def get_collection_url(self):
        return urljoin(
            self.base_url, "v2/inthreat/collections", self.collection, "objects"
        )

    def get_object_url(self, ids: Iterable):
        return urljoin(self.base_url, "v2/inthreat/objects", ",".join(ids))

    def get_relationship_url(self, ids: Iterable):
        return urljoin(self.base_url, "v2/inthreat/relationships", ",".join(ids))

    def get_file_url(self, item_id: str, file_hash: str):
        return urljoin(
            self.base_url, "v2/inthreat/objects", item_id, "files", file_hash
        )

    @staticmethod
    def generate_first_cursor() -> str:
        """
        Generate the first cursor to interrogate the API
        so we don't start at the beginning.
        """
        start = f"{(datetime.utcnow() - timedelta(hours=1)).isoformat()}Z"
        return base64.b64encode(start.encode("utf-8")).decode("utf-8")

    @staticmethod
    def chunks(items, chunk_size):
        """
        Yield successive n-sized chunks from items.
        """
        for i in range(0, len(items), chunk_size):
            yield items[i : i + chunk_size]

    def _run(self, cursor):
        params = {"limit": self.limit, "cursor": cursor}

        data = self._send_request(self.get_collection_url(), params)
        if not data:
            return cursor

        next_cursor = data["next_cursor"] or cursor  # In case next_cursor is None
        items = data["items"]
        if not items:
            return next_cursor

        items = self._retrieve_references(items)
        items = self._clean_ic_fields(items)
        self._add_files_to_items(items)
        bundle = self.helper.stix2_create_bundle(items)
        self.helper.send_stix2_bundle(bundle, update=True)

        self.helper.set_state({"last_cursor": next_cursor})
        if len(items) < self.limit:
            # We got the last results
            return next_cursor

        # More results to fetch
        return self._run(next_cursor)

    def _clean_ic_fields(self, items: List[Dict]) -> List[Dict]:
        """
        Remove fields specific to the Intelligence Center
        that will not add value in OpenCTI
        """
        return [
            {
                field: value
                for field, value in item.items()
                if not self._field_to_ignore(field)
            }
            for item in items
        ]

    @staticmethod
    def _field_to_ignore(field: str) -> bool:
        to_ignore = [
            "x_ic_impacted_locations",
            "x_ic_impacted_sectors",
        ]
        return (
            (field.startswith("x_ic") or field.startswith("x_inthreat"))
            and (field.endswith("ref") or field.endswith("refs"))
        ) or field in to_ignore

    def _retrieve_references(
        self, items: List[Dict], current_depth: int = 0
    ) -> List[Dict]:
        """
        Retrieve the references that appears in the given items.

        To avoid having an infinite recursion a safe guard has been implemented.
        """
        if current_depth == 5:
            # Safe guard to avoid infinite recursion if an object was not found for example
            return items

        items = self._update_mapped_refs(items)
        to_fetch = self._get_missing_refs(items)
        for ref in list(to_fetch):
            if ref in self._cache:
                items.append(self._cache[ref])
                to_fetch.remove(ref)
        if not to_fetch:
            return items

        objects_to_fetch = [i for i in to_fetch if not i.startswith("relationship--")]
        items += self._retrieve_by_ids(objects_to_fetch, self.get_object_url)

        relationships_to_fetch = [i for i in to_fetch if i.startswith("relationship--")]
        items += self._retrieve_by_ids(
            relationships_to_fetch, self.get_relationship_url
        )
        return self._retrieve_references(items, current_depth + 1)

    def _get_missing_refs(self, items: List[Dict]) -> Set:
        """
        Get the object's references that are missing
        """
        ids = {item["id"] for item in items}
        refs = set()
        for item in items:
            refs.update(item.get("object_marking_refs", []))
            if item.get("created_by_ref"):
                refs.add(item["created_by_ref"])
            if item["type"] == "report":
                object_refs = [
                    ref
                    for ref in item.get("object_refs", [])
                    if not self._is_mapped_ref(ref)
                ]
                refs.update(object_refs)
            if item["type"] == "relationship":
                if not self._is_mapped_ref(item["source_ref"]):
                    refs.add(item["source_ref"])
                if not self._is_mapped_ref(item["target_ref"]):
                    refs.add(item["target_ref"])
        return refs - ids

    def _is_mapped_ref(self, ref: str) -> bool:
        """
        Whether or not the reference is a mapped one.
        """
        return (
            ref in self._geography_mapping.values()
            or ref in self._sectors_mapping.values()
        )

    def _update_mapped_refs(self, items: List[Dict]):
        """
        Update references that are mapped between SEKOIA and OpenCTI.

        This way we will be able to create links with OpenCTI own sectors and locations.
        """
        for item in items:
            if item.get("object_marking_refs"):
                item["object_marking_refs"] = self._replace_mapped_refs(
                    item["object_marking_refs"]
                )
            if item.get("object_refs"):
                item["object_refs"] = self._replace_mapped_refs(item["object_refs"])
            if item.get("source_ref"):
                item["source_ref"] = self._get_mapped_ref(item["source_ref"])
            if item.get("target_ref"):
                item["target_ref"] = self._get_mapped_ref(item["target_ref"])
        return items

    def _replace_mapped_refs(self, refs: List):
        for i, ref in enumerate(refs):
            refs[i] = self._get_mapped_ref(ref)
        return refs

    def _get_mapped_ref(self, ref: str):
        if ref in self._geography_mapping:
            return self._geography_mapping[ref]
        if ref in self._sectors_mapping:
            return self._sectors_mapping[ref]
        return ref

    def _retrieve_by_ids(self, ids, url_callback):
        """
        Fetch the items for the given ids.
        """
        items = []
        for chunk in self.chunks(ids, 40):
            url = url_callback(chunk)
            res = self._send_request(url)
            if not res:
                continue
            if "items" in res:
                items.extend(res["items"])
                for item in res["items"]:
                    self._clean_and_add_to_cache(item)
            if "data" in res:
                items.append(res["data"])
                self._clean_and_add_to_cache(res["data"])
        return items

    def _clean_and_add_to_cache(self, item):
        """
        Add item to the cache only if it is an identity or a marking definition
        """
        if item["id"].startswith("marking-definition--") or item["id"].startswith(
            "identity--"
        ):
            if item["id"].startswith("marking-definition--"):
                item.pop("object_marking_refs", None)
            self._cache[item["id"]] = item

    def _send_request(self, url, params=None, binary=False):
        """
        Sends the HTTP request and handle the errors
        """
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            res = requests.get(url, params=params, headers=headers)
            res.raise_for_status()
            if binary:
                return res.content
            return res.json()
        except RequestException as ex:
            if ex.response:
                error = f"Request failed with status: {ex.response.status_code}"
                self.helper.log_error(error)
            else:
                self.helper.log_error(str(ex))
            return None

    def _load_data_sets(self):
        # Mapping between SEKOIA sectors/locations and OpenCTI ones
        self.helper.log_info("Loading locations mapping")
        with open("./data/geography_mapping.json") as fp:
            self._geography_mapping: Dict = json.load(fp)

        self.helper.log_info("Loading sectors mapping")
        with open("./data/sectors_mapping.json") as fp:
            self._sectors_mapping: Dict = json.load(fp)

        # Adds OpenCTI sectors/locations to cache
        self.helper.log_info("Loading OpenCTI sectors")
        with open("./data/sectors.json") as fp:
            objects = json.load(fp)["objects"]
            for sector in objects:
                self._clean_and_add_to_cache(sector)

        self.helper.log_info("Loading OpenCTI locations")
        with open("./data/geography.json") as fp:
            for geography in json.load(fp)["objects"]:
                self._clean_and_add_to_cache(geography)

    def _add_files_to_items(self, items: List[Dict]):
        for item in items:
            if not item.get("x_inthreat_uploaded_files"):
                continue
            item["x_opencti_files"] = []
            for file in item.get("x_inthreat_uploaded_files", []):
                url = self.get_file_url(item["id"], file["sha256"])
                data = self._send_request(url, binary=True)
                if data:
                    item["x_opencti_files"].append(
                        {
                            "name": file["file_name"],
                            "data": base64.b64encode(data).decode("utf-8"),
                            "mime_type": file.get("mime_type", "text/plain"),
                        }
                    )


if __name__ == "__main__":
    try:
        sekoiaConnector = Sekoia()
        sekoiaConnector.run()
    except Exception:
        time.sleep(10)
        exit(0)
