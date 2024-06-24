import datetime
import os
import time
from abc import ABC, abstractmethod
from queue import Queue
from typing import Any, Iterator, Union

import titan_client
from pycti import OpenCTIConnectorHelper
from stix2 import Bundle
from titan_client.titan_stix import STIXMapperSettings
from titan_client.titan_stix.exceptions import EmptyBundle

from .. import HelperRequest

HERE = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(HERE, "..", "..", "__version__")) as fh:
    version = fh.read().strip()


class Intel471Stream(ABC):
    """
    Base class for all streams. When creating new stream, inherit from this class and provide following class vars:

    - label - this is a unique name which will be used as part of the config variables names and a part of cursor's name
              for example: label=cves, env var=INTEL471_INTERVAL_CVES, config var=intel471.interval_cves, etc.
    - api_payload_objects_key - property of the object from API's response under which the objects to process are stored
                                for example for /cve/reports endpoint cves are stored under "cve_reports" key (snake_case always)
    - api_class_name, api_method_name - name of the class and the method from `titan_client` for fetching the objects
                                        for example for CVEs it'll be "VulnerabilitiesApi" and "cve_reports_get"

    And implement following methods, if default implementation is not sufficient (mostly for stream endpoints):

    - def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
      implement the logic for building arguments for the API call, including initial history and cursor handling
    - def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
      implement the logic for extracting value used for cursor from the API's response.
    """

    label = None
    api_payload_objects_key = None
    api_class_name = None
    api_method_name = None

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        api_username: str,
        api_key: str,
        in_queue: Queue,
        out_queue: Queue,
        initial_history: int = None,
        update_existing_data: bool = False,
        proxy_url: Union[str, None] = None,
    ) -> None:
        self.helper = helper
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.api_config = titan_client.Configuration(
            username=api_username, password=api_key
        )
        self.api_config.proxy = proxy_url
        self.update_existing_data = update_existing_data
        if initial_history:
            self.initial_history = initial_history
        else:
            self.initial_history = int((datetime.datetime.utcnow()).timestamp() * 1000)

    @property
    def cursor_name(self) -> str:
        return f"{self.label}_cursor"

    def run(self) -> None:
        for bundle in self.get_bundles():
            self.send_to_server(bundle)

    def get_bundles(self) -> Iterator[Bundle]:
        cursor = self._get_cursor()
        offsets = self._get_offsets()
        with titan_client.ApiClient(self.api_config) as api_client:
            api_client.user_agent = (
                f"{api_client.user_agent}; OpenCTI-Connector/{version}"
            )
            api_instance = getattr(titan_client, self.api_class_name)(api_client)
        while True:
            kwargs = self._get_api_kwargs(cursor)
            for offset in offsets:
                if offset is not None:
                    kwargs["offset"] = offset
                self.helper.log_info(
                    "{} calls Titan API with arguments: {}.".format(
                        self.__class__.__name__, str(kwargs)
                    )
                )
                api_response = getattr(api_instance, self.api_method_name)(**kwargs)
                api_payload_objects = (
                    getattr(api_response, self.api_payload_objects_key) or []
                )
                self.helper.log_info(
                    "{} got {} items from Titan API.".format(
                        self.__class__.__name__, len(api_payload_objects)
                    )
                )
                if not api_payload_objects:
                    break
                cursor = self._get_cursor_value(api_response)
                try:
                    bundle = api_response.to_stix(
                        STIXMapperSettings(
                            titan_client, api_client, report_attachments_opencti=True
                        )
                    )
                except EmptyBundle:
                    self.helper.log_info(
                        f"{self.__class__.__name__} got empty bundle from STIX converter."
                    )
                else:
                    yield bundle
            else:
                # executes when there was no break in the inner loop, i.e. there are still results to fetch,
                # but we need to shift dates as the offset was exhausted
                self._update_cursor(cursor)
                continue
            self._update_cursor(cursor)
            break

    def send_to_server(self, bundle: Bundle) -> None:
        self.helper.log_info(
            f"{self.__class__.__name__} sends bundle with {len(bundle.objects)} objects"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, self.__class__.__name__
        )
        self.helper.send_stix2_bundle(
            bundle.serialize(), work_id=work_id, update=self.update_existing_data
        )
        self.helper.api.work.to_processed(work_id, "Done")

    def _get_cursor(self) -> Union[str, None]:
        return self._get_state(self.cursor_name)

    def _update_cursor(self, value: str) -> None:
        return self._set_state(self.cursor_name, value)

    def _get_state(self, key: str):
        self.helper.log_debug("Sending task to helper handler to get the state")
        self.out_queue.put(
            HelperRequest(operation=HelperRequest.Operation.GET, stream=self.label)
        )
        self.helper.log_debug("Waiting for helper handler to get state")
        cursor = self.in_queue.get().get(key)
        self.helper.log_debug("Got data from helper handler")
        return cursor

    def _set_state(self, key: str, value: str):
        self.helper.log_debug("Sending task to helper handler to save state")
        self.out_queue.put(
            HelperRequest(
                operation=HelperRequest.Operation.UPDATE,
                stream=self.label,
                data={key: value},
            )
        )
        self.helper.log_debug("Waiting for ACK from helper handler to save state")
        self.in_queue.get()
        self.helper.log_debug("Got ack for save state, proceeding")

    @staticmethod
    def _get_ttl_hash(seconds=10_000):
        """Return the same value withing `seconds` time period"""
        return round(time.time() / seconds)

    @abstractmethod
    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        raise NotImplementedError

    def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
        return str(
            getattr(api_response, self.api_payload_objects_key)[-1].activity.last + 1
        )

    def _get_offsets(self) -> list[Union[None, int]]:
        return list(range(0, 1100, 100))
