import json
import re
import uuid
from typing import Tuple

import requests
from pycti import OpenCTIConnectorHelper
from taxii_post_connector.settings import ConnectorSettings


def parse_version(version) -> Tuple[int, int, int]:
    """
    Extracts major.minor.patch as a tuple of ints from a version string.
    Accepts inputs like '2.1', '2.1.3', 'v2.1', etc.
    """
    nums = [int(n) for n in re.findall(r"\d+", str(version))]
    if not nums:
        raise ValueError(f"Invalid version: {version!r}")
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2]


def accept_header_by_taxii_version(version: str) -> str:
    if parse_version(version) >= (2, 1, 0):
        return f"application/taxii+json; version={version}"
    else:
        return f"application/vnd.oasis.taxii+json; version={version}"


def content_type_by_stix_version(version: str) -> str:
    if parse_version(version) >= (2, 1, 0):
        return f"application/stix+json; version={version}"
    else:
        return f"application/vnd.oasis.stix+json; version={version}"


class TaxiiPostConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config.taxii
        self.helper = helper

    def check_stream_id(self):
        """
        In case of stream_id configuration is missing, raise ValueError
        """
        if (
            not self.helper.connect_live_stream_id
            or self.helper.connect_live_stream_id.lower() == "changeme"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _prepare_object(self, data):
        """
        Apply the configured transformations to a single STIX object before it
        is posted to the TAXII server.

        Returns the transformed object, or ``None`` when the object must not be
        posted at all. When ``delete_created_by_ref`` is enabled the author
        identity referenced by ``created_by_ref`` is stripped from every object;
        the identity object itself would otherwise still reach the server as its
        own stream event, so it is dropped here to honor the configuration.
        """
        data_object = data
        if self.config.delete_created_by_ref and data_object.get("type") == "identity":
            return None
        data_object["spec_version"] = self.config.stix_version
        if (
            self.config.delete_marking_definition
            and "object_marking_refs" in data_object
        ):
            del data_object["object_marking_refs"]
        if self.config.delete_created_by_ref and "created_by_ref" in data_object:
            del data_object["created_by_ref"]
        if self.config.stix_version != "2.1":
            del data_object["extensions"]
            for key in (
                "spec_version",
                "revoked",
                "confidence",
                "lang",
                "pattern_type",
                "pattern_version",
                "is_family",
            ):
                if key in data_object:
                    del data_object[key]
        return data_object

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message")
        self.helper.log_info("Processing the object " + data["id"])
        base = str(self.config.url).rstrip("/")
        url = (
            base
            + "/"
            + self.config.api_root
            + "/collections/"
            + self.config.collection_id
            + "/objects/"
        )
        headers = {
            "Content-Type": content_type_by_stix_version(self.config.stix_version),
            "Accept": accept_header_by_taxii_version(self.config.version),
        }
        try:
            data_object = self._prepare_object(data)
            if data_object is None:
                self.helper.log_info(
                    "Skipping identity object "
                    + data["id"]
                    + " (delete_created_by_ref is enabled)"
                )
                return
            bundle = {
                "type": "bundle",
                "spec_version": self.config.stix_version,
                "id": "bundle--" + str(uuid.uuid4()),
                "objects": [data_object],
            }
            if self.config.token is not None:
                self.helper.log_info("Posting to TAXII URL (using token): " + url)
                self.helper.log_info(str(bundle))
                headers["Authorization"] = (
                    "Bearer " + self.config.token.get_secret_value()
                )
                response = requests.post(
                    url,
                    headers=headers,
                    json=bundle,
                    verify=self.config.ssl_verify,
                )
                response.raise_for_status()
            else:
                self.helper.log_info("Posting to TAXII URL (using basic auth): " + url)
                self.helper.log_info(str(bundle))
                response = requests.post(
                    url,
                    headers=headers,
                    auth=(
                        (
                            self.config.login.get_secret_value()
                            if self.config.login is not None
                            else None
                        ),
                        (
                            self.config.password.get_secret_value()
                            if self.config.password
                            else None
                        ),
                    ),
                    json=bundle,
                    verify=self.config.ssl_verify,
                )
                response.raise_for_status()
            self.helper.log_info("TAXII Response: " + str(response.content))
        except Exception as e:
            self.helper.log_error(str(e))

    def start(self):
        self.check_stream_id()
        self.helper.listen_stream(self._process_message)
