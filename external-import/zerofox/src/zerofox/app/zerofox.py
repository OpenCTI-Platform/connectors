# standard library
from datetime import datetime, timedelta
from typing import Any, Generator

# first-party
from http_.http_request import http_request
from zerofox.app.endpoints import CTIEndpoint


class ZeroFox:
    """ZeroFox client for the different Cyber Threat Intelligence Endpoints."""

    def __init__(self, user, token) -> None:
        """Client requires user and token for retrieving CTI token."""
        self._base_url = "https://api.zerofox.com"
        print("retrieving CTI token...")
        self.cti_token = {
            "token": self._get_cti_authorization_token(username=user, token=token),
            "registered": datetime.now(),
        }
        self.user = user
        self.token = token
        print("CTI token retrieved successfully!")

    def fetch_feed(
        self, endpoint: CTIEndpoint, last_run: datetime
    ) -> Generator[Any, None, None]:
        return self._cti_request(
            constructor=endpoint.factory,
            endpoint=endpoint.value,
            params={endpoint.after_key: last_run.isoformat()},
        )

    def _cti_request(
        self,
        constructor: type,
        endpoint,
        params=None,
        data=None,
    ) -> Generator[Any, None, None]:
        """Perform requests on ZeroFox's CTI endpoints.

        :param endpoint: Specific CTI endpoint
        :param params: The request's query parameters
        :param data: The request's body parameters
        :return: Returns the content of the response received from the API.
        """
        headers = self._get_cti_request_header()

        url = f"{self._base_url}/cti/{endpoint}/"
        response = http_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
            data=data,
            ok_code=200,
        )

        for result in response["results"]:
            yield constructor(**result)
        while response["next"]:
            response = http_request(
                method="GET",
                headers=headers,
                ok_code=200,
                url=response["next"],
            )
            for result in response["results"]:
                yield constructor(**result)

    def _get_cti_authorization_token(self, username, token) -> str:
        """Retrieve uthorization token for the CTI feed."""
        response_content = http_request(
            method="POST",
            ok_code=200,
            url=f"{self._base_url}/auth/token/",
            data=dict(username=username, password=token),
        )
        access = response_content.get("access", "")
        return access

    def _get_cti_request_header(self):
        now = datetime.now()
        if now - self.cti_token["registered"] <= timedelta(minutes=29):
            return self._build_auth_header(self.cti_token["token"])
        else:
            self.cti_token["token"] = self._get_cti_authorization_token(
                self.user, self.token
            )
            self.cti_token["registered"] = now
            return self._build_auth_header(self.cti_token["token"])

    def _build_auth_header(self, token):
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "zf-source": "OpenCTI",
        }
