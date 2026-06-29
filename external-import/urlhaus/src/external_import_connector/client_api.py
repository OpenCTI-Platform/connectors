import csv
import zipfile
from io import BytesIO, StringIO
from typing import Generator

import requests
from dateutil.parser import parse


class ConnectorClient:
    def __init__(self, helper, config, state):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.state = state

        # Define headers in session and update when needed
        self.session = requests.Session()

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def _get_csv_text(self, response) -> str:
        """
        Extract CSV text from response. Handles both plain text CSV
        and ZIP archives (used by the full database dump).
        """
        content_type = response.headers.get("content-type", "")
        if "zip" in content_type or self.config.urlhaus.csv_url.endswith(".zip") or self._is_zip(response.content):
            with zipfile.ZipFile(BytesIO(response.content)) as zf:
                # The zip contains a single file (csv.txt)
                name = zf.namelist()[0]
                return zf.read(name).decode("utf-8", errors="replace")
        return response.text

    @staticmethod
    def _is_zip(content: bytes) -> bool:
        """Check if content starts with the ZIP magic bytes."""
        return content[:4] == b"PK\x03\x04"

    def get_entities(self, params=None) -> Generator[list, None, None]:
        """
        retrieve all URLs in URLHaus Database
        :param params: undefine
        :return: lists of url
        """
        try:
            response = self._request_data(self.config.urlhaus.csv_url, params=params)
            csv_text = self._get_csv_text(response)
            lines = csv_text.splitlines()
            rdr = csv.reader(
                (line for line in lines if line and line[0] != "#")
            )

            ## the csv-file hast the following columns
            # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            bundle_objects = []
            for i, row in enumerate(rdr):
                entry_date = parse(row[1])

                if i % 50000 == 0:
                    self.helper.log_info(
                        f"Process entry {i} with dateadded='{entry_date.strftime('%Y-%m-%d %H:%M:%S')}'"
                    )
                    yield bundle_objects
                    bundle_objects = []

                # skip entry if newer events already processed in the past
                if self.state.last_processed_entry_old > entry_date.timestamp():
                    continue
                self.state.last_processed_entry_new = max(
                    entry_date.timestamp(), self.state.last_processed_entry_new
                )

                if self.config.urlhaus.import_offline is False and row[3] == "offline":
                    continue

                bundle_objects.append(row)

            yield bundle_objects
        except Exception as err:
            self.helper.connector_logger.error(err)
