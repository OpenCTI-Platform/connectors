from prometheus_client import Counter


class Metrics:
    """Metrics for the connector.

    The http server is already started by the OpenCTI connector helper.
    """

    def __init__(self, name: str):
        self.name = name

        self._sent_messages_counter = Counter(
            "sent_messages_counter", "Number of sent messages to RabbitMQ", ["name"]
        )
        self._sent_error_counter = Counter(
            "sent_error_counter",
            "Number of error sending messages to RabbitMQ",
            ["name"],
        )

        self._read_files_counter = Counter(
            "read_files_counter", "Number of files read from minio", ["name"]
        )
        self._file_wrong_order = Counter(
            "file_wrong_order", "Number of files with incorrect order", ["name"]
        )

    def send(self):
        self._sent_messages_counter.labels(self.name).inc()

    def send_error(self):
        self._sent_error_counter.labels(self.name).inc()

    def read(self):
        self._read_files_counter.labels(self.name).inc()

    def wrong_file_order(self):
        self._file_wrong_order.labels(self.name).inc()
