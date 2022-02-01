import datetime
from abc import ABC, abstractmethod
from typing import Iterator

from stix2 import Bundle

import titan_client
from pycti import OpenCTIConnectorHelper


class Intel471Stream(ABC):

    def __init__(self, helper: OpenCTIConnectorHelper, api_username: str, api_key: str, lookback: int = None) -> None:
        self.helper = helper
        self.api_config = titan_client.Configuration(username=api_username, password=api_key)
        if lookback:
            self.lookback = lookback
        else:
            self.lookback = int((datetime.datetime.utcnow() - datetime.timedelta(days=1)).timestamp() * 1000)

    def run(self) -> None:
        for bundle in self.get_bundle():
            self.send_to_server(bundle)

    @abstractmethod
    def get_bundle(self) -> Iterator[Bundle]:
        raise NotImplemented

    def send_to_server(self, bundle: Bundle) -> None:
        self.helper.log_info(f"{self.__class__.__name__} sends bundle with {len(bundle.objects)} objects")
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, self.__class__.__name__)
        # TODO: read 'update' from env vars
        self.helper.send_stix2_bundle(bundle.serialize(), work_id=work_id, update=False)
        self.helper.api.work.to_processed(work_id, "Done")
