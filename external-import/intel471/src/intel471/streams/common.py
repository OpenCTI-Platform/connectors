import datetime
from abc import ABC, abstractmethod
from typing import Iterator

from stix2 import Bundle

import titan_client
from pycti import OpenCTIConnectorHelper
from titan_client.titan_stix.exceptions import EmptyBundle


class Intel471Stream(ABC):

    ref = None
    api_payload_objects_key = None
    api_class_name = None
    api_method_name = None

    def __init__(self, helper: OpenCTIConnectorHelper,
                 api_username: str,
                 api_key: str,
                 initial_history: int = None,
                 update_existing_data: bool = False) -> None:
        self.helper = helper
        self.api_config = titan_client.Configuration(username=api_username, password=api_key)
        self.update_existing_data = update_existing_data
        if initial_history:
            self.initial_history = initial_history
        else:
            self.initial_history = int((datetime.datetime.utcnow()).timestamp() * 1000)

    @property
    def cursor_name(self):
        return f"{self.ref}_cursor"

    def run(self) -> None:
        for bundle in self.get_bundle():
            self.send_to_server(bundle)

    def get_bundle(self) -> Iterator[Bundle]:
        state = self.helper.get_state() or {}
        cursor = state.get(self.cursor_name)
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
            state[self.cursor_name] = cursor
            self.helper.set_state(state)
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

    @abstractmethod
    def _get_api_kwargs(self, cursor):
        raise NotImplemented

    @abstractmethod
    def _get_cursor_value(self, api_response):
        raise NotImplemented
