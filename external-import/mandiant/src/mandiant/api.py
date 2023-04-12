from typing import Dict, Iterable, List, Union
from datetime import datetime, timedelta
from urllib.parse import urljoin
import requests
import logging
import time


logging.getLogger("urllib3").setLevel(logging.WARNING)

logger = logging.getLogger("mandiant-api")


class MandiantAPI:
    api_url: str = "https://api.intelligence.mandiant.com"
    token_format: str = "Bearer {token}"
    max_retries: int = 3
    last_query_time = None
    endpoints: Dict[str, str] = {
        "token": "/token",
        "reports": "v4/reports",
        "report": "v4/report/{id}",
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

    def __init__(self, key_id: str, key_secret: str):
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
            logger.error("Authentication failed")
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

            if response.status_code == 200:
                return response

            if response.status_code == 429:
                logger.warning("Rate limit exceeded. Waiting 30 seconds ...")
                time.sleep(30)
                continue

            if response.status_code in [401, 403]:
                logger.debug("Refreshing token ...")
                retries += 1
                self._authenticate()
                continue

            logger.error(f"An unknown error occurred, code: {response.status_code}.")
            raise ValueError(f"An unknown error occurred, code: {response.status_code}")

    def _process(
        self,
        name: str,
        parameters: Dict[str, str] = {},
        item_id: Union[str, int] = None,
        required: List[str] = [],
        result: str = "objects",
        mode: str = "json",
    ) -> Iterable[object]:

        url = self._get_endpoint(name=name, item_id=item_id, **parameters)

        required_parameters = {param: parameters[param] for param in required}

        while True:
            response = self._query(url, self.modes.get(mode))

            if response is None:
                yield response
                return

            if item_id:
                if mode == "pdf":
                    yield response.content
                else:
                    yield response.json()
                return

            data = response.json()

            for item in data.get(result):
                yield item

            next_parameter = data.get("next", None)

            if next_parameter is None:
                return

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
        include_reports: bool = False,
        include_campaigns: bool = False,
    ) -> Iterable[Dict]:
        return self._process(
            name="indicators",
            parameters={
                "start_epoch": start_epoch,
                "end_epoch": end_epoch,
                "limit": limit,
                "gte_mscore": gte_mscore,
                "exclude_osint": exclude_osint,
                "include_reports": include_reports,
                "include_campaigns": include_campaigns
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
    ) -> Iterable[Dict]:
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

    def actors(self, limit: int = 1000, offset: int = 0) -> Iterable[Dict]:
        return self._process(
            name="actors",
            parameters={"limit": limit, "offset": offset},
            result="threat-actors",
        )

    def vulnerabilities(self, start_epoch: int = None, end_epoch: int = None, limit: int = 1000) -> Iterable[Dict]:
        return self._process(
            name="vulnerabilities",
            parameters={
                "start_epoch": start_epoch,
                "end_epoch": end_epoch,
                "limit": limit,
            },
            result="vulnerability",
        )

    def campaigns(
        self, start_epoch: int = None, end_epoch: int = None, limit: int = 1000, offset: int = 0
    ) -> Iterable[Dict]:
        return self._process(
            name="campaigns",
            parameters={
                "start_epoch": start_epoch,
                "end_epoch": end_epoch,
                "limit": limit,
                "offset": offset,
            },
            result="campaigns",
        )

    def malwares(self, limit: int = 5000, offset: int = 0) -> Iterable[Dict]:
        return self._process(
            name="malwares",
            parameters={"offset": offset, "limit": limit},
            result="malware",
        )

    def report(self, report_id: str, mode: str = "json") -> Union[Dict, bytes]:
        return next(self._process(name="report", item_id=report_id, mode=mode))

    def actor(self, actor_id: str, mode: str = "json") -> Dict:
        return next(self._process(name="actor", item_id=actor_id, mode=mode))

    def malware(self, malware_id: str) -> Dict:
        return next(self._process(name="malware", item_id=malware_id))

    def campaign(self, campaign_id: str) -> Dict:
        return next(self._process(name="campaign", item_id=campaign_id))

    def campaign_timeline(self, campaign_id: str) -> Dict:
        return next(self._process(name="campaign_timeline", item_id=campaign_id))

    def campaign_indicators(self, campaign_id: str) -> Dict:
        return next(self._process(name="campaign_indicators", item_id=campaign_id))

    def campaign_attack_patterns(self, campaign_id: str) -> Dict:
        return next(self._process(name="campaign_attack_patterns", item_id=campaign_id))

    def campaign_reports(self, campaign_id: str) -> Dict:
        return next(self._process(name="campaign_reports", item_id=campaign_id))
