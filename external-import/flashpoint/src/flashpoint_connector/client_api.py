import base64

import requests


class ConnectorClient:

    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.config.api_key,
        }
        self.session = requests.Session()
        self.session.headers.update(headers)
        self.flashpoint_api_url = "https://api.flashpoint.io"

    def get_communities_doc(self, doc_id):
        """
        :param doc_id:
        :return:
        """
        url = self.flashpoint_api_url + "/sources/v2/communities/" + doc_id
        params = {}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def communities_search(self, query, start_date):
        """
        :param query:
        :param start_date:
        :return:
        """
        url = self.flashpoint_api_url + "/sources/v2/communities"
        page = 0
        body_params = {
            "query": query,
            "include": {"date": {"start": start_date, "end": ""}},
            "size": "1000",
            "sort": {"date": "asc"},
            "page": page,
        }
        results = []
        has_more = True
        while has_more:
            response = self.session.post(url, json=body_params)
            response.raise_for_status()
            data = response.json()
            results.extend(data.get("items"))
            if len(results) < data.get("total").get("value"):
                page += 1
            else:
                has_more = False
        return results

    def get_media_doc(self, doc_id):
        """
        :param doc_id:
        :return:
        """
        url = self.flashpoint_api_url + "/sources/v2/media/" + doc_id
        params = {}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def get_media(self, media_id):
        """
        :return:
        """
        url = self.flashpoint_api_url + "/sources/v1/media"
        params = {"cdn": False, "asset_id": media_id}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return base64.b64encode(response.content), response.headers.get("Content-Type")

    def get_alerts(self, start_date):
        """
        :return:
        """
        alerts = []
        url = self.flashpoint_api_url + "/alert-management/v1/notifications"
        params = {"created_after": start_date}
        has_more = True
        while has_more:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            if data.get("pagination").get("next"):
                url = data.get("pagination").get("next")
            else:
                has_more = False
            alerts.extend(data.get("items"))
        return alerts

    def get_reports(self, start_date):
        """
        :return:
        """
        url = self.flashpoint_api_url + "/finished-intelligence/v1/reports"
        limit = 100
        params = {
            "since": start_date,
            "limit": limit,
            "skip": 0,
            "sort": "updated_at:asc",
        }
        has_more = True
        reports = []
        while has_more:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            response_json = response.json()
            total = response_json.get("total")
            reports.extend(response_json.get("data", []))
            params["skip"] += limit
            if len(reports) == total:
                has_more = False
        return reports

    def get_misp_feed_manifest(self):
        """
        :return:
        """
        url = (
            self.flashpoint_api_url
            + "/technical-intelligence/v1/misp-feed/manifest.json"
        )
        response = self.session.get(url)
        response.raise_for_status()
        data = response.json()
        return data

    def get_misp_event_file(self, filename):
        """
        :return:
        """
        url = (
            self.flashpoint_api_url + "/technical-intelligence/v1/misp-feed/" + filename
        )
        response = self.session.get(url)
        response.raise_for_status()
        data = response.json()
        return data
