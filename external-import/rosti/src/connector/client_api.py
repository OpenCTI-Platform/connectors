import requests


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = {"X-Api-Key": self.config.api_key}
        self.session = requests.Session()
        self.session.headers.update(headers)

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

    def get_reports(self, since=None) -> list:
        """
        Retrieve all full reports, handling pagination.
        :param since: Optional since to filter the date from which to pull the reports
        :return: A list of dicts of the complete collection of reports
        """
        try:
            all_reports = []
            offset = 0
            report_ids = []

            # Step 1: Fetch all report summaries and collect IDs
            while True:
                params = {"fromdate": since, "offset": offset}
                response = self._request_data(self.config.api_base_url + "reports", params=params)
                if response is None:
                    break

                page_data = response.json()
                report_ids.extend([report.get("id") for report in page_data if report.get("id")])

                pagination_count = int(response.headers.get("X-Pagination-Count", 0))
                pagination_limit = int(response.headers.get("X-Pagination-Limit", 100))

                if pagination_count < pagination_limit:
                    break

                offset += pagination_limit

            # Step 2: Fetch full reports
            for report_id in report_ids:
                full_report_response = self._request_data(f"{self.config.api_base_url}reports/{report_id}")
                if full_report_response is not None:
                    all_reports.append(full_report_response.json())

            return all_reports
        except Exception as err:
            self.helper.connector_logger.error(err)
            return []
