from prometheus_client import Counter, Gauge, start_http_server


class Metrics:
    def __init__(self, name: str, addr: str, port: int) -> None:
        self.name = name
        self.addr = addr
        self.port = port

        self._processed_messages_counter = Counter(
            "processed_messages", "Number of processed messages", ["name", "action"]
        )
        self._current_state_gauge = Gauge(
            "current_state", "Current connector state", ["name"]
        )

    def message(self, action: str) -> None:
        """
        Set processed messages counter from an event
        It contains the action in string
        :param action: Action in string
        :return: None
        """
        self._processed_messages_counter.labels(self.name, action).inc()

    def state(self, event_id: str) -> None:
        """
        Set current state metric from an event id.

        An event id looks like 1679004823824-0, it contains time information
        about when the event was generated.
        :param event_id: Event ID in string
        :return: None
        """

        ts = int(event_id.split("-")[0])
        self._current_state_gauge.labels(self.name).set(ts)

    def start_server(self) -> None:
        """
        Start the server for metrics
        :return: None
        """
        start_http_server(self.port, addr=self.addr)

    def handle_metrics(self, msg) -> None:
        """
        Set metrics message and metrics state
        :param msg: Message event from stream
        :return: None
        """
        self.message(msg.event)
        self.state(msg.id)
