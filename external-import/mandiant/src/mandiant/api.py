import logging
import time
from typing import Dict, Iterable, List, Union
from urllib.parse import urljoin

import requests

logging.getLogger("urllib3").setLevel(logging.WARNING)


class MandiantAPI:
    api_url: str = "https://api.intelligence.mandiant.com"
    token_format: str = "Bearer {token}"
    max_retries: int = 3
    endpoints: Dict[str, str] = {
        "token": "/token",
        "reports": "v4/reports",
        "report": "v4/report/{id}",
        "actors": "v4/actor",
        "actor": "v4/actor/{id}",
        "malwares": "v4/malware",
        "malware": "v4/malware/{id}",
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
        self.__authenticate()

    def __get_endpoint(self, name: str, item_id: str = None, **kwargs) -> str:
        request = requests.models.PreparedRequest()

        path = self.endpoints.get(name)
        if item_id:
            path = path.format(id=item_id)

        endpoint = urljoin(self.api_url, path)
        request.prepare_url(endpoint, kwargs)
        return request.url

    def __authenticate(self) -> None:
        response = requests.post(
            url=self.__get_endpoint("token"),
            auth=self.auth,
            data={"grant_type": "client_credentials"},
            headers={
                "accept": "application/json",
                "x-app-name": "opencti-connector",
            },
        )

        if response.status_code != 200:
            raise ValueError("Mandiant Authentication failed")

        self.token = response.json().get("access_token")
        print(self.token)

    def __query(self, url: str, accept: str) -> Union[requests.Response, None]:
        retries = 0

        while True:
            if self.max_retries == retries:
                return None

            headers = {
                "accept": accept,
                "x-app-name": "opencti-connector",
                "authorization": self.token_format.format(token=self.token),
            }

            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                return response

            if response.status_code == 429:
                time.sleep(30)
                continue

            if response.status_code in [401, 403]:
                retries += 1
                self.__authenticate()
                continue

            raise ValueError(f"An unknown error occurred, code: {response.status_code}")

    def __process(
        self,
        name: str,
        parameters: Dict[str, str] = {},
        item_id: Union[str, int] = None,
        required: List[str] = [],
        result: str = "objects",
        mode: str = "json",
    ) -> Iterable[object]:
        url = self.__get_endpoint(name=name, item_id=item_id, **parameters)

        required_parameters = {param: parameters[param] for param in required}

        while True:
            response = self.__query(url, self.modes.get(mode))

            if response is None:
                yield None
                return

            if item_id:
                if mode == "pdf":
                    yield response.content
                else:
                    yield response.json()
                return

            data = response.json()

            for item in data.get(result, []):
                yield item

            next_parameter = data.get("next", None)

            if next_parameter is None:
                return

            url = self.__get_endpoint(
                name=name, next=next_parameter, **required_parameters
            )

            time.sleep(1)

    def indicators(
        self,
        start_epoch: int,
        end_epoch: int = None,
        limit: int = None,
        gte_mscore: int = None,
        exclude_osint: bool = None,
    ) -> Iterable[Dict]:
        return self.__process(
            name="indicators",
            parameters={
                "start_epoch": start_epoch,
                "end_epoch": end_epoch,
                "limit": limit,
                "gte_mscore": gte_mscore,
                "exclude_osint": exclude_osint,
            },
            required=["start_epoch"],
            result="indicators",
        )

    def reports(
        self,
        start_epoch: int = None,
        end_epoch: int = None,
        limit: int = None,
        offset: int = None,
    ) -> Iterable[Dict]:
        return self.__process(
            name="reports",
            parameters={
                "start_epoch": start_epoch,
                "end_epoch": end_epoch,
                "limit": limit,
                "offset": offset,
            },
            result="objects",
        )

    def actors(self, limit: int = None, offset: int = None) -> Iterable[Dict]:
        return self.__process(
            name="actors",
            parameters={"limit": limit, "offset": offset},
            result="threat-actors",
        )

    def vulnerabilities(
        self, start_epoch: int = None, end_epoch: int = None, limit: int = None
    ) -> Iterable[Dict]:
        return self.__process(
            name="vulnerabilities",
            parameters={
                "start_epoch": start_epoch,
                "end_epoch": end_epoch,
                "limit": limit,
            },
            result="vulnerability",
        )

    def malwares(self, limit: int = None, offset: int = None) -> Iterable[Dict]:
        return self.__process(
            name="malwares",
            parameters={"offset": offset, "limit": limit},
            result="malware",
        )

    def report(self, report_id: str, mode: str = "json") -> Union[Dict, bytes]:
        return next(self.__process(name="report", item_id=report_id, mode=mode))

    def actor(self, actor_id: str, mode: str = "json") -> Dict:
        return next(self.__process(name="actor", item_id=actor_id, mode=mode))

    def malware(self, malware_id: str) -> Dict:
        return next(self.__process(name="malware", item_id=malware_id))
