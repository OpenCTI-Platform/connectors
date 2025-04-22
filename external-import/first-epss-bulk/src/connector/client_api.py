"""Client API."""

import csv
import gzip
import io
from datetime import datetime, timezone
from typing import Any, Optional, Union

import requests


class ConnectorClient:
    # pylint: disable=too-few-public-methods
    """Client API."""

    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = {}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def request_data(
        self, api_url: str, params=None
    ) -> Optional[dict[Union[str, Any], dict[str, float]]]:
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            utc_date = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
            url = f"{api_url}/epss_scores-{utc_date}.csv.gz"
            response = self.session.get(url, params=params)
            response.raise_for_status()

            with gzip.open(io.BytesIO(response.content), "rt", encoding="utf-8") as f:
                # Skip first line
                next(f)
                # Read csv by defaut taking in the headers cve,epss,percentile
                reader = csv.DictReader(f)
                epss_data = {
                    row["cve"]: {
                        "epss": float(row["epss"]),
                        "percentile": float(row["percentile"]),
                    }
                    for row in reader
                }

            return epss_data
        except requests.exceptions.RequestException as e:
            self.helper.logger.error(f"Error during download: {e}")
        except gzip.BadGzipFile as e:
            self.helper.logger.error(f"Error during unzipping: {e}")
        except Exception as e:
            self.helper.logger.error(f"Unknown error: {e}")

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

        return None
