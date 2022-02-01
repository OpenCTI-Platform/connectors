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

        api_username = get_config_variable(
            "INTEL471_API_USERNAME", ["intel471", "api_username"], config
        )
        api_key = get_config_variable(
            "INTEL471_API_KEY", ["intel471", "api_username"], config
        )

        for stream_class, env_var, config_var in (
                (Intel471IndicatorsStream, "INTEL471_INTERVAL_INDICATORS", "interval_indicators"),
                (Intel471CVEsStream, "INTEL471_INTERVAL_CVES", "interval_cves")):
            if interval := get_config_variable(env_var, ["intel471", config_var], config, True, 0):
                self.add_job(stream_class(self.helper, api_username, api_key), interval)

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def run(self) -> None:
        self.scheduler.start()

    def add_job(self, stream_class: Intel471Stream, interval: int):
        self.scheduler.add_job(stream_class.run, name=stream_class.__class__.__name__, trigger="interval", minutes=interval)

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
