import csv
from io import StringIO
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

    def get_entities(self, params=None) -> Generator[list, None, None]:
        """
        retrieve all URLs in URLHaus Database
        :param params: undefine
        :return: lists of url
        """
        try:
            response = self._request_data(self.config.urlhaus.csv_url, params=params)
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
        except Exception as err:
            self.helper.connector_logger.error(err)
