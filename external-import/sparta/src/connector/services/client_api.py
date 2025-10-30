import json
import ssl
import urllib
from typing import Optional

import pycti
from stix2 import TLP_WHITE, Identity


class SpartaClient:
    def __init__(self, helper, config):
        """Initialize the client with necessary configurations"""
        self.helper = helper
        self.config = config
        self.base_url = self.config.sparta.base_url

    def add_author(self, stix_objects):
        author = Identity(
            id=pycti.Identity.generate_id(
                identity_class="organization", name="The Aerospace Corporation"
            ),
            name="The Aerospace Corporation",
            identity_class="organization",
            object_marking_refs=[TLP_WHITE],
            external_references=[
                {
                    "source_name": "Aerospace Sparta Main URL",
                    "url": "https://sparta.aerospace.org/",
                }
            ],
        )
        for stix_object in stix_objects:
            stix_object["created_by_ref"] = author["id"]
        stix_objects.append(json.loads(author.serialize()))
        return stix_objects

    def add_marking_definition(self, stix_objects):
        for stix_object in stix_objects:
            stix_object["object_marking_refs"] = [str(TLP_WHITE.id)]
        stix_objects.append(json.loads(TLP_WHITE.serialize()))
        return stix_objects

    def retrieve_data(self) -> Optional[dict]:
        try:
            # Fetch json bundle from SPARTA
            serialized_bundle = (
                urllib.request.urlopen(
                    str(self.base_url),
                    context=ssl.create_default_context(),
                )
                .read()
                .decode("utf-8")
            )
            # Convert the data to python dictionary
            stix_bundle = json.loads(serialized_bundle)
            stix_objects = stix_bundle["objects"]
            stix_objects = self.add_author(stix_objects)
            stix_objects = self.add_marking_definition(stix_objects)
            stix_bundle["objects"] = stix_objects
            return stix_bundle
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.connector_logger.error(
                f"Error retrieving url {self.base_url}: {urllib_error}"
            )
            self.helper.metric.inc("client_error_count")
        return None
