import os
import signal

import yaml
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.schedulers.blocking import BlockingScheduler
from yaml.parser import ParserError

from pycti import OpenCTIConnectorHelper, get_config_variable
from .streams.common import Intel471Stream
from .streams.indicators import Intel471IndicatorsStream
from .streams.cves import Intel471CVEsStream


class Intel471Connector:
    def __init__(self) -> None:
        config = self._init_config()
        self.scheduler = self._init_scheduler()
        self.helper = OpenCTIConnectorHelper(config)

        update_existing_data = bool(get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA", ["connector", "update_existing_data"], config,
        ))

        api_username = get_config_variable(
            "INTEL471_API_USERNAME", ["intel471", "api_username"], config
        )
        api_key = get_config_variable(
            "INTEL471_API_KEY", ["intel471", "api_username"], config
        )

        for stream_class in (Intel471IndicatorsStream, Intel471CVEsStream):
            if interval := get_config_variable(
                    f"INTEL471_INTERVAL_{stream_class.ref}".upper(),
                    ["intel471", f"interval_{stream_class.ref}"],
                    config,
                    isNumber=True,
                    default=0):
                initial_history = get_config_variable(
                    f"INTEL471_INITIAL_HISTORY_{stream_class.ref}".upper(),
                    ["intel471", f"initial_history_{stream_class.ref}"],
                    config,
                    isNumber=True,
                    default=0)
                self.add_job(
                    stream_class(self.helper, api_username, api_key, initial_history, update_existing_data),
                    interval)

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def run(self) -> None:
        self.scheduler.start()

    def add_job(self, stream_obj: Intel471Stream, interval: int):
        self.scheduler.add_job(stream_obj.run, name=stream_obj.__class__.__name__, trigger="interval", minutes=interval)

    @staticmethod
    def _init_scheduler() -> BlockingScheduler:
        return BlockingScheduler(
            jobstores={"default": MemoryJobStore()},
            job_defaults={"coalesce": True}
        )

    @staticmethod
    def _init_config() -> dict:
        config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml")
        try:
            with open(config_file_path) as fh:
                return yaml.load(fh, Loader=yaml.FullLoader)
        except (FileNotFoundError, ParserError):
            return {}

    def _signal_handler(self, *args):
        print("Shutting down")
        self.scheduler.shutdown()
        self.helper.stop()
