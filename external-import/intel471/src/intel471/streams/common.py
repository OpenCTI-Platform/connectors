import datetime
from abc import ABC, abstractmethod
from queue import Queue
from typing import Iterator, Union, Any

from stix2 import Bundle

import titan_client
from pycti import OpenCTIConnectorHelper
from titan_client.titan_stix.exceptions import EmptyBundle
from .. import HelperRequest


class Intel471Stream(ABC):

    label = None
    api_payload_objects_key = None
    api_class_name = None
    api_method_name = None

    def __init__(self, helper: OpenCTIConnectorHelper,
                 api_username: str,
                 api_key: str,
                 in_queue: Queue,
                 out_queue: Queue,
                 initial_history: int = None,
                 update_existing_data: bool = False) -> None:
        self.helper = helper
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.api_config = titan_client.Configuration(username=api_username, password=api_key)
        self.update_existing_data = update_existing_data
        if initial_history:
            self.initial_history = initial_history
        else:
            self.initial_history = int((datetime.datetime.utcnow()).timestamp() * 1000)

    @property
    def cursor_name(self) -> str:
        return f"{self.label}_cursor"

    def run(self) -> None:
        for bundle in self.get_bundle():
            self.send_to_server(bundle)

    def get_bundle(self) -> Iterator[Bundle]:
        cursor = self._fetch_cursor()
        with titan_client.ApiClient(self.api_config) as api_client:
            api_instance = getattr(titan_client, self.api_class_name)(api_client)
        while True:
            kwargs = self._get_api_kwargs(cursor)
            self.helper.log_info("{} calls Titan API with arguments: {}.".format(self.__class__.__name__, str(kwargs)))
            api_response = getattr(api_instance, self.api_method_name)(**kwargs)
            api_payload_objects = getattr(api_response, self.api_payload_objects_key) or []
            self.helper.log_info("{} got {} items from Titan API.".format(
                self.__class__.__name__,
                len(api_payload_objects)))
            if not api_payload_objects:
                break
            cursor = self._get_cursor_value(api_response)
            self._update_cursor(cursor)
            try:
                bundle = api_response.to_stix()
            except EmptyBundle:
                self.helper.log_info(f"{self.__class__.__name__} got empty bundle from STIX converter.")
            else:
                yield bundle

    def send_to_server(self, bundle: Bundle) -> None:
        self.helper.log_info(f"{self.__class__.__name__} sends bundle with {len(bundle.objects)} objects")
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, self.__class__.__name__)
        self.helper.send_stix2_bundle(bundle.serialize(), work_id=work_id, update=self.update_existing_data)
        self.helper.api.work.to_processed(work_id, "Done")

    def _fetch_cursor(self) -> Union[str, None]:
        self.helper.log_debug("Sending task to helper handler to get the state")
        self.out_queue.put(HelperRequest(stream=self.label, operation=HelperRequest.Operation.GET))
        self.helper.log_debug("Waiting for helper handler to get state")
        cursor = self.in_queue.get().get(self.cursor_name)
        self.helper.log_debug("Got data from helper handler")
        return cursor

    def _update_cursor(self, value: str) -> None:
        self.helper.log_debug("Sending task to helper handler to save state")
        self.out_queue.put(HelperRequest(stream=self.label, operation=HelperRequest.Operation.UPDATE, data={self.cursor_name: value}))
        self.helper.log_debug("Waiting for ACK from helper handler to save state")
        self.in_queue.get()
        self.helper.log_debug("Got ack for save state, proceeding")

    @abstractmethod
    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        raise NotImplemented

    @abstractmethod
    def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
        raise NotImplemented
