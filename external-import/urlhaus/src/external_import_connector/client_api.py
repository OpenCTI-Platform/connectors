import csv
from http import HTTPStatus
from io import StringIO
from typing import Generator

import requests
from connectors_sdk.exceptions.error import DataRetrievalError
from dateutil.parser import parse

# Seconds to wait for the server; the recent export is about 30 MB.
REQUEST_TIMEOUT = 300


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

    def _request_data(self, api_url: str, params=None) -> requests.Response:
        """
        Internal method to handle API requests
        :return: the HTTP response
        :raises DataRetrievalError: when the download fails, so that the run is
            reported as failed instead of successful with no data
        """
        # The export URL contains the Auth-Key: never log it, and re-raise with
        # `from None`, because requests quotes the URL in its error messages
        # (see "Use `from None` intentionally, to remove sensitive values" in
        # connectors-sdk/docs/HOW-TO-Handle-errors-in-connectors.md).
        self.helper.connector_logger.info("[API] Downloading URLhaus export")
        try:
            response = self.session.get(api_url, params=params, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response
        except requests.HTTPError as err:
            status = err.response.status_code
            # Use the standard phrase, not the server's reason, which a proxy
            # could fill with the request URL.
            try:
                phrase = f" {HTTPStatus(status).phrase}"
            except ValueError:
                phrase = ""
            hint = (
                ": check URLHAUS_AUTH_KEY or URLHAUS_CSV_URL"
                if status in (401, 403)
                else ""
            )
            raise DataRetrievalError(
                f"URLhaus export download failed: HTTP {status}{phrase}{hint}"
            ) from None
        except requests.RequestException as err:
            raise DataRetrievalError(
                f"URLhaus export download failed ({type(err).__name__})"
            ) from None

    def get_entities(self, params=None) -> Generator[list, None, None]:
        """
        retrieve all URLs in URLHaus Database
        :param params: undefine
        :return: lists of url
        """
        # Errors are not swallowed here: a failed download or an unreadable
        # file must reach process_message() and mark the work in error.
        response = self._request_data(self.config.urlhaus.export_url, params=params)
        file = StringIO(response.text)
        rdr = csv.reader(filter(lambda row: row[0] != "#", file))

        ## the csv-file hast the following columns
        # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        bundle_objects = []
        for i, row in enumerate(rdr):
            entry_date = parse(row[1])

            if i % 1000 == 0:
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
