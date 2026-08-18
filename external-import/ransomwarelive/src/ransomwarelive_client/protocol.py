from typing import Protocol

MAX_RETRIES = 5
RETRY_BACKOFF_FACTOR = 60
RETRY_BACKOFF_JITTER = 30
REQUEST_TIMEOUT_SECONDS = 30


class RansomwareAPIClientProtocol(Protocol):
    def get_groups(self) -> list[dict]: ...

    def get_recent_victims(self) -> list[dict]: ...

    def get_victims(self, year: int, month: int) -> list[dict]: ...
