import os
import signal
from queue import Queue

import yaml
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import BaseScheduler
from pycti import OpenCTIConnectorHelper, get_config_variable
from yaml.parser import ParserError

from . import HelperRequest
from .streams.common import Intel471Stream
from .streams.cves import Intel471CVEsStream
from .streams.indicators import Intel471IndicatorsStream
from .streams.iocs import Intel471IOCsStream
from .streams.yara import Intel471YARAStream


class Intel471Connector:
    def __init__(self) -> None:
        config: dict = self._init_config()
        self.scheduler: BaseScheduler = self._init_scheduler()
        self.helper = OpenCTIConnectorHelper(config)
        # We'll use queues to coordinate helper state reads/writes from threaded streams
        self.in_queue = Queue()
        self.out_queues: dict[str, Queue] = {}

        update_existing_data = bool(
            get_config_variable(
                "CONNECTOR_UPDATE_EXISTING_DATA",
                ["connector", "update_existing_data"],
                config,
            )
        )

        api_username = get_config_variable(
            "INTEL471_API_USERNAME", ["intel471", "api_username"], config
        )
        api_key = get_config_variable(
            "INTEL471_API_KEY", ["intel471", "api_key"], config
        )
        proxy_url = get_config_variable("INTEL471_PROXY", ["intel471", "proxy"], config)

        for stream_class in (
            Intel471IndicatorsStream,
            Intel471CVEsStream,
            Intel471YARAStream,
            Intel471IOCsStream,
        ):
            if interval := get_config_variable(
                f"INTEL471_INTERVAL_{stream_class.label}".upper(),
                ["intel471", f"interval_{stream_class.label}"],
                config,
                isNumber=True,
                default=0,
            ):
                self.out_queues[stream_class.label] = Queue()
                initial_history = get_config_variable(
                    f"INTEL471_INITIAL_HISTORY_{stream_class.label}".upper(),
                    ["intel471", f"initial_history_{stream_class.label}"],
                    config,
                    isNumber=True,
                    default=0,
                )
                self.add_job(
                    stream_class(
                        self.helper,
                        api_username,
                        api_key,
                        self.out_queues[stream_class.label],
                        self.in_queue,
                        initial_history,
                        update_existing_data,
                        proxy_url,
                    ),
                    interval,
                )

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def run(self) -> None:
        self.scheduler.start()
        self.handle_helper_state()  # main loop

    def handle_helper_state(self) -> None:
        """
        As there are several data streams, each running in its own thread (through self.scheduler), it is necessary to
        coordinate reads and writes of helper state to avoid race conditions. Each stream class is initialised
        with IN and OUT queue, so each time it needs to read or write the state it requests it through
        a shared queue which is then consumed by this method. The result (the state dict, or
        simple ACK that the state was updated) is being communicated back using a separate queue dedicated for
        the specific stream.
        """
        while True:
            request: HelperRequest = self.in_queue.get()
            if request.operation == HelperRequest.Operation.KILL:
                return
            out_queue: Queue = self.out_queues[request.stream]
            self.helper.log_debug(f"Got task {str(request)}")
            state = self.helper.get_state() or {}
            if request.operation == HelperRequest.Operation.GET:
                out_queue.put(state)
            elif request.operation == HelperRequest.Operation.UPDATE:
                for k, v in request.data.items():
                    state[k] = v
                self.helper.set_state(state)
                out_queue.put("ACK")
            self.helper.log_info(f"Put ACK into queue for task {str(request)}")

    def add_job(self, stream_obj: Intel471Stream, interval: int) -> None:
        self.scheduler.add_job(
            stream_obj.run,
            name=stream_obj.__class__.__name__,
            trigger="interval",
            minutes=interval,
        )

    @staticmethod
    def _init_scheduler() -> BaseScheduler:
        return BackgroundScheduler(
            jobstores={"default": MemoryJobStore()},
            job_defaults={"coalesce": True},
            timezone="UTC",
        )

    @staticmethod
    def _init_config() -> dict:
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "config.yml"
        )
        try:
            with open(config_file_path) as fh:
                return yaml.load(fh, Loader=yaml.FullLoader)
        except (FileNotFoundError, ParserError):
            return {}

    def _signal_handler(self, *args) -> None:
        self.helper.log_info("Shutting down")
        self.scheduler.shutdown()
        self.helper.stop()
        self.in_queue.put(HelperRequest(operation=HelperRequest.Operation.KILL))
