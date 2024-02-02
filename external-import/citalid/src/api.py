import base64
import urllib.parse

import requests


class Client:
    @staticmethod
    def _parse_url(url: str) -> str:
        if not url.lower().startswith("https://") and url.lower() != "":
            url = "https://" + url
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lstrip("/")
        return urllib.parse.urlunparse(parsed._replace(path=path))

    def __init__(self, customer_sub_domain_url, language="en"):
        self.client_id = "0RcQ2BmuJRRsZKvY1Xf1gdjiwYRZhQKBNOxY9KOI"
        self.customer_sub_domain_url = self._parse_url(customer_sub_domain_url)
        self.connection_service_base_url = f"{customer_sub_domain_url}/auth"
        self.api_base_url = (
            f"{customer_sub_domain_url}/facade/risk-intelligence-center/api/v1"
        )
        self.headers = {}
        self.set_language(language)

    def set_language(self, language):
        self.headers["Accept-Language"] = language

    def login(self, user, password):
        data = f"grant_type=password&username={urllib.parse.quote(user)}&password={urllib.parse.quote(password)}"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {base64.b64encode(f'{self.client_id}:'.encode()).decode()}",
        }
        response = requests.post(
            f"{self.connection_service_base_url}/o/token/", data=data, headers=headers
        )
        self.check_response(response)
        content = response.json()
        self.headers["Authorization"] = f"Bearer {content['access_token']}"

    def call(self, method, url, **kwargs):
        kwargs["headers"] = {**self.headers, **kwargs.get("headers", {})}
        res = requests.request(method, f"{self.api_base_url}/{url}", **kwargs)
        self.check_response(res)
        return res.json() if res.content else None

    def get_last_version(self):
        return self.call("GET", "stix-bundles/versions/latest/")

    def get_latest_bundle(self):
        return self.call("GET", "stix-bundles/versions/latest/download/")

    @staticmethod
    def check_response(res):
        if not (200 <= res.status_code < 300):
            raise Exception(
                f"{res.status_code} error for url {res.url}: {res.content[:100]}"
            )
