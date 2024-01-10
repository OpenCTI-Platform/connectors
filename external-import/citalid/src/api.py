import json

from time import sleep

import requests, base64
import urllib.parse


class Client:
    def __init__(
            self, connection_service_base_url, api_base_url, language="en"
    ):
        #TODO this should be replaced by specific client ID for OpenCTI
        self.client_id = "0RcQ2BmuJRRsZKvY1Xf1gdjiwYRZhQKBNOxY9KOI"
        self.connection_service_base_url = connection_service_base_url
        # self.connection_service_base_url = f"{customer_instance_url}/auth"
        self.api_base_url = api_base_url
        # self.api_base_url = f"{customer_instance_url}/facade/risk-intelligence-center/api/v1'
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
        return self.call("GET", "stix-bundles/versions/latest")

    def get_bundle(self):
        return self.call("GET", "stix-bundles/versions/latest/download")

    @staticmethod
    def check_response(res):
        if not (200 <= res.status_code < 300):
            raise Exception(
                f"{res.status_code} error for url {res.url}: {res.content[:100]}"
            )

