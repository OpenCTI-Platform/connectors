import time
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Union
from urllib.parse import urljoin

import requests
from pycti import OpenCTIConnectorHelper

OFFSET_PAGINATION = 100


class MandiantAPI:
    api_url: str = "https://api.intelligence.mandiant.com"
    token_format: str = "Bearer {token}"
    max_retries: int = 3
    last_query_time = None
    endpoints: Dict[str, str] = {
        "token": "/token",
        "reports": "v4/reports",
        "report": "v4/report/{id}",
        "report_indicators": "v4/report/{id}/indicators",
        "actors": "v4/actor",
        "actor": "v4/actor/{id}",
        "malwares": "v4/malware",
        "malware": "v4/malware/{id}",
        "campaigns": "v4/campaign",
        "campaign": "v4/campaign/{id}",
        "campaign_timeline": "v4/campaign/{id}/timeline",
        "campaign_indicators": "v4/campaign/{id}/indicators",
        "campaign_attack_patterns": "v4/campaign/{id}/attack-pattern",
        "campaign_reports": "v4/campaign/{id}/reports",
        "indicators": "v4/indicator",
        "vulnerabilities": "v4/vulnerability",
    }
    modes: Dict[str, str] = {
        "json": "application/json",
        "pdf": "application/pdf",
        "stix": "application/stix+json;version=2.1",
    }

    def __init__(self, helper: OpenCTIConnectorHelper, key_id: str, key_secret: str):
        self.helper = helper
        self.auth = requests.auth.HTTPBasicAuth(key_id, key_secret)
        self._authenticate()

    def _set_last_query_time(self):
        self.last_query_time = datetime.now()

    def _wait_before_next_query(self):
        if not self.last_query_time:
            return

        while True:
            if datetime.now() - self.last_query_time > timedelta(seconds=1):
                break

            time.sleep(0.1)

    def _get_endpoint(self, name: str, item_id: str = None, **kwargs) -> str:
        request = requests.models.PreparedRequest()

        path = self.endpoints.get(name)
        if item_id:
            path = path.format(id=item_id)

        endpoint = urljoin(self.api_url, path)
        request.prepare_url(endpoint, kwargs)
        return request.url

    def _authenticate(self) -> None:
        response = requests.post(
            url=self._get_endpoint("token"),
            auth=self.auth,
            data={"grant_type": "client_credentials"},
            headers={
                "accept": "application/json",
                "x-app-name": "opencti-connector",
            },
        )

        if response.status_code != 200:
            self.helper.connector_logger.error("Authentication failed")
            raise ValueError("Mandiant Authentication failed")

        self.token = response.json().get("access_token")

    def _query(self, url: str, accept: str) -> Union[requests.Response, None]:
        retries = 0

        while True:
            if self.max_retries == retries:
                return None

            headers = {
                "accept": accept,
                "x-app-name": "opencti-connector",
                "authorization": self.token_format.format(token=self.token),
            }

            self._wait_before_next_query()

            response = requests.get(url, headers=headers)

            self._set_last_query_time()

            if 200 <= response.status_code < 300:
                return response

            if response.status_code == 429:
                self.helper.connector_logger.warning(
                    "Rate limit exceeded. Waiting 30 seconds ..."
                )
                time.sleep(30)
                continue

            if response.status_code in [401, 403]:
                self.helper.connector_logger.debug("Refreshing token ...")
                retries += 1
                self._authenticate()
                continue

            meta = {
                "status_code": response.status_code,
                "response": response.text,
                "url": url,
                "headers": str(headers),
            }
            self.helper.connector_logger.error("An unknown error occurred", meta)
            raise ValueError("An unknown error occurred")

    def _process(
        self,
        name: str,
        parameters: Dict[str, Union[str, int]] = {},
        item_id: Union[str, int] = None,
        required: List[str] = [],
        result: str = "objects",
        mode: str = "json",
    ) -> Union[Dict, bytes, List[Dict]]:
        url = self._get_endpoint(name=name, item_id=item_id, **parameters)
        required_parameters = {param: parameters[param] for param in required}
        mandiant_data = []
        while True:
            self.helper.connector_logger.info(url)
            response = self._query(url, self.modes.get(mode))
            if response is None:
                return mandiant_data

            if item_id:
                if mode == "pdf":
                    return response.content
                else:
                    return response.json()

            data = response.json()
            data_response = data.get(result)
            next_parameter = data.get("next", None)

            if data_response is None:
                return mandiant_data

            for item in data_response:
                mandiant_data.append(item)

            if next_parameter is None:
                return mandiant_data

            url = self._get_endpoint(
                name=name,
                next=next_parameter,
                **required_parameters,
            )

    def indicators(
        self,
        start_epoch: int,
        end_epoch: int = None,
        limit: int = 1000,
        gte_mscore: int = None,
        exclude_osint: bool = True,
        include_reports: bool = True,
        include_campaigns: bool = True,
    ) -> [Dict]:
        return self._process(
            name="indicators",
            parameters={
                "start_epoch": start_epoch,
                "end_epoch": end_epoch,
                "limit": limit,
                "gte_mscore": gte_mscore,
                "exclude_osint": exclude_osint,
                "include_reports": include_reports,
                "include_campaigns": include_campaigns,
            },
            required=["start_epoch"],
            result="indicators",
        )

    def reports(
        self,
        start_epoch: int = None,
        end_epoch: int = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> [Dict]:
        return self._process(
            name="reports",
            parameters={
                "start_epoch": start_epoch,
                "end_epoch": end_epoch,
                "limit": limit,
                "offset": offset,
            },
            result="objects",
        )

    def vulnerabilities(
        self,
        start_epoch: int = None,
        end_epoch: int = None,
        limit: int = 1000,
        sort_by: str = "last_update",
        sort_order: str = "asc",
    ) -> [Dict]:
        return self._process(
            name="vulnerabilities",
            parameters={
                "start_epoch": start_epoch,
                "end_epoch": end_epoch,
                "limit": limit,
                "sort_by": sort_by,
                "sort_order": sort_order,
            },
            result="vulnerability",
        )

    def actors(self, limit: int = OFFSET_PAGINATION, offset: int = 0) -> Iterable[Dict]:
        return self._process(
            name="actors",
            parameters={"limit": limit, "offset": offset},
            result="threat-actors",
        )

    def campaigns(self, limit: int = OFFSET_PAGINATION, offset: int = 0) -> [Dict]:
        return self._process(
            name="campaigns",
            parameters={"limit": limit, "offset": offset},
            result="campaigns",
        )

    def malwares(self, limit: int = OFFSET_PAGINATION, offset: int = 0) -> [Dict]:
        return self._process(
            name="malwares",
            parameters={"offset": offset, "limit": limit},
            result="malware",
        )

    def report(self, report_id: str, mode: str = "json") -> Union[Dict, bytes]:
        return self._process(name="report", item_id=report_id, mode=mode)

    def report_indicators(self, report_id: str) -> Dict:
        return self._process(name="report_indicators", item_id=report_id)

    def actor(self, actor_id: str, mode: str = "json") -> Dict:
        return self._process(name="actor", item_id=actor_id, mode=mode)

    def malware(self, malware_id: str) -> Dict:
        return self._process(name="malware", item_id=malware_id)

    def campaign(self, campaign_id: str) -> Dict:
        return self._process(name="campaign", item_id=campaign_id)

    def campaign_timeline(self, campaign_id: str) -> Dict:
        return self._process(name="campaign_timeline", item_id=campaign_id)

    def campaign_indicators(self, campaign_id: str) -> Dict:
        return self._process(name="campaign_indicators", item_id=campaign_id)

    def campaign_attack_patterns(self, campaign_id: str) -> Dict:
        return self._process(name="campaign_attack_patterns", item_id=campaign_id)

    def campaign_reports(self, campaign_id: str) -> Dict:
        return self._process(name="campaign_reports", item_id=campaign_id)
