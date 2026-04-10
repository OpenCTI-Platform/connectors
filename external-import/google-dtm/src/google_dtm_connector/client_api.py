from typing import Any

import requests


class GoogleDTMAPIClient:

    def __init__(self, helper, api_key: str) -> None:
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.base_url = "https://www.virustotal.com/api/v3/dtm"
        headers = {"accept": "application/json", "x-apikey": api_key}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params)
            # print(response.content)
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

    def get_dtm_alerts(self, since_date, alert_severity, alert_type) -> list[Any]:
        """
        :param since_date:
        :param alert_severity:
        :param alert_type:
        :return:
        """
        alerts = []
        # size between 0 & 25 max
        params = {
            "since": since_date,
            "sort": "updated_at",
            "size": 25,
            "severity": alert_severity,
            "alert_type": alert_type,
            "order": "asc",
        }
        dtm_alerts_url = self.base_url + "/alerts"
        has_more = True
        page = 1
        self.helper.connector_logger.info(
            "[API] Start fetching DTM alerts",
            {
                "since": since_date,
                "severity": alert_severity,
                "alert_type": alert_type,
            },
        )
        while has_more:
            try:
                response = self.session.get(dtm_alerts_url, params=params)
                response.raise_for_status()
                data = response.json()
                page_alerts = data.get("alerts", [])
                if page_alerts:
                    alerts.extend(page_alerts)

                self.helper.connector_logger.info(
                    "[API] DTM alerts page fetched",
                    {
                        "page": page,
                        "fetched_count": len(page_alerts),
                        "total_count": len(alerts),
                    },
                )

                next_url = response.links.get("next", {}).get("url")
                if next_url:
                    self.helper.connector_logger.info(
                        "[API] Continue DTM alerts pagination",
                        {"page": page + 1},
                    )
                    dtm_alerts_url = next_url
                    params = {}
                    page += 1
                else:
                    has_more = False
            except Exception as err:
                ex = Exception(
                    "An exception occurred while fetching alerts, error: {}".format(
                        str(err)
                    )
                )
                raise ex

        self.helper.connector_logger.info(
            "[API] Finished fetching DTM alerts",
            {"total_count": len(alerts), "pages": page},
        )
        return alerts
