import signal
from queue import Queue

from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import BaseScheduler
from intel471.common import HelperRequest
from intel471.settings import ConnectorSettings
from intel471.streams.breach_alerts import Intel471BreachAlertsStream
from intel471.streams.common import Intel471Stream
from intel471.streams.cves import Intel471CVEsStream
from intel471.streams.indicators import Intel471IndicatorsStream
from intel471.streams.malware_reports import Intel471MalwareReportsStream
from intel471.streams.reports import Intel471ReportsStream
from intel471.streams.spot_reports import Intel471SpotReportsStream
from intel471.streams.yara import Intel471YARAStream
from pycti import OpenCTIConnectorHelper


class Intel471Connector:

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper

        self.scheduler: BaseScheduler = self._init_scheduler()
        self.in_queue = Queue()
        self.out_queues: dict[str, Queue] = {}
        update_existing_data = False
        api_username = self.config.intel471.api_username
        api_key = self.config.intel471.api_key.get_secret_value()
        proxy_url = self.config.intel471.proxy
        ioc_score = self.config.intel471.ioc_score
        backend = self.config.intel471.backend
        for stream_class in (
            Intel471IndicatorsStream,
            Intel471CVEsStream,
            Intel471YARAStream,
            Intel471ReportsStream,
            Intel471BreachAlertsStream,
            Intel471SpotReportsStream,
            Intel471MalwareReportsStream,
        ):
            if interval := getattr(
                self.config.intel471, f"interval_{stream_class.group_label}"
            ):
                self.out_queues[stream_class.label] = Queue()
                initial_history = getattr(
                    self.config.intel471, f"initial_history_{stream_class.group_label}"
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
                        backend,
                        ioc_score,
                    ),
                    interval,
                )
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def run(self) -> None:
        self.scheduler.start()
        self.handle_helper_state()

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

    def _signal_handler(self, *args) -> None:
        self.helper.log_info("Shutting down")
        self.scheduler.shutdown()
        self.helper.stop()
        self.in_queue.put(HelperRequest(operation=HelperRequest.Operation.KILL))
