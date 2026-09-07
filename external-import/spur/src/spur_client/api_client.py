import gzip
import io
import json
from typing import Iterator

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import SecretStr


class SpurClient:  # pylint: disable=too-few-public-methods
    def __init__(self, helper: OpenCTIConnectorHelper, api_key: SecretStr):
        self.helper = helper
        self.session = requests.Session()
        self.session.headers.update({"Token": api_key.get_secret_value()})

    def stream_feed(self, feed_url: str) -> Iterator[dict]:
        """Stream a gzipped NDJSON Spur feed, yielding one IP Context dict per line."""
        self.helper.connector_logger.info(
            "[SPUR] Downloading feed", meta={"url": feed_url}
        )
        try:
            response = self.session.get(feed_url, stream=True, timeout=300)
            response.raise_for_status()
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[SPUR] Failed to download feed",
                meta={"url": feed_url, "error": str(err)},
            )
            return

        try:
            with gzip.GzipFile(fileobj=response.raw) as gz:
                for line in io.TextIOWrapper(gz, encoding="utf-8"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as err:
                        self.helper.connector_logger.warning(
                            "[SPUR] Skipping malformed JSON line",
                            meta={"error": str(err)},
                        )
        except Exception as err:
            self.helper.connector_logger.error(
                "[SPUR] Error reading feed stream",
                meta={"url": feed_url, "error": str(err)},
            )
