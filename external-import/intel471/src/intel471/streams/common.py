from abc import ABC, abstractmethod
from typing import Iterator
from uuid import uuid4

from stix2 import Bundle

import titan_client
from pycti import OpenCTIConnectorHelper


class Intel471Stream(ABC):

    def __init__(self, helper: OpenCTIConnectorHelper, api_username: str, api_key: str) -> None:
        self.helper = helper
        self.api_config = titan_client.Configuration(username=api_username, password=api_key)

    def run(self) -> None:
        for bundle in self.get_bundle():
            self.send_to_server(bundle)

    @abstractmethod
    def get_bundle(self) -> Iterator[Bundle]:
        raise NotImplemented

    def send_to_server(self, bundle: Bundle) -> None:
        """
        Sends a STIX2 bundle to OpenCTI Server
        Args:
            bundle (list(dict)): STIX2 bundle represented as a list of dicts
        """
        self.helper.log_info(f"Sending Bundle to server with " f'{len(bundle.objects)} objects')
        # TODO: read 'update' from env vars
        self.helper.send_stix2_bundle(bundle.serialize(), work_id=str(uuid4()), update=False)
