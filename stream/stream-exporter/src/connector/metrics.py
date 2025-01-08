from datetime import datetime

from prometheus_client import Counter, Gauge


class Metrics:
    """Metrics for the connector.

    The http server is already started by the OpenCTI connector helper.
    """

    def __init__(self, name: str):
        self.name = name

        self._processed_messages_counter = Counter(
            "processed_messages", "Number of processed messages", ["name", "action"]
        )
        self._written_files_counter = Counter(
            "written_files_counter", "Number of written files on minio", ["name"]
        )
        self._write_error_counter = Counter(
            "write_error_counter", "Number of error writing files on minio", ["name"]
        )
        self._current_state_gauge = Gauge(
            "current_state", "Current connector state", ["name"]
        )
        self._last_written_state_gauge = Gauge(
            "last_written_state", "Last written connector state", ["name"]
        )

        self._recover_until_state_gauge = Gauge(
            "recover_until_state", "Recover until connector state", ["name"]
        )

    def msg(self, action: str):
        self._processed_messages_counter.labels(self.name, action).inc()

    def write(self):
        self._written_files_counter.labels(self.name).inc()

    def write_error(self):
        self._write_error_counter.labels(self.name).inc()

    def state(self, event_id: str):
        """Set current state metric from an event id.

        An event id looks like 1679004823824-0, it contains time information
        about when the event was generated."""

        ts = int(event_id.split("-")[0])
        self._current_state_gauge.labels(self.name).set(ts)

    def state_last_written(self, event_id: str):
        """Set the last written state, once written on minio."""
        ts = int(event_id.split("-")[0])
        self._last_written_state_gauge.labels(self.name).set(ts)

    def state_recover_until(self, recover: str):
        """Set the recover until state"""
        self._recover_until_state_gauge.labels(self.name).set(
            datetime.fromisoformat(recover).timestamp() * 1000
        )
