import json
import logging
from typing import TypeAlias

import requests

logger = logging.getLogger(__name__)

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]
DepApiItem: TypeAlias = dict[str, JsonValue]


class DepClient:
    def __init__(
        self,
        *,
        login_endpoint: str,
        api_endpoint: str,
        api_key: str | None,
        username: str | None,
        password: str | None,
        client_id: str,
        dataset: str,
        extended_results: bool,
    ) -> None:
        self.login_endpoint = login_endpoint
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.username = username
        self.password = password
        self.client_id = client_id
        self.dataset = dataset
        self.extended_results = extended_results

    def authenticate(self) -> str:
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        }
        payload = {
            "AuthParameters": {"USERNAME": self.username, "PASSWORD": self.password},
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": self.client_id,
        }
        response = requests.post(
            self.login_endpoint,
            headers=headers,
            json=payload,
            timeout=30,
        )
        response.raise_for_status()
        auth_payload: dict[str, dict[str, str]] = response.json()
        token = auth_payload["AuthenticationResult"]["IdToken"]
        if not token:
            error = "Unable to retrieve IdToken from authentication response"
            raise ValueError(error)
        return token

    def fetch_raw(
        self,
        start_date: str,
        end_date: str,
    ) -> list[DepApiItem]:
        token = self.authenticate()
        params: dict[str, str] = {
            "ts": start_date,
            "te": end_date,
            "dset": self.dataset,
            "full": "true",
        }
        if self.extended_results:
            params["extended"] = "true"

        headers = {
            "X-Api-Key": self.api_key,
            "Authorization": token,
        }

        response = requests.get(
            self.api_endpoint,
            headers=headers,
            params=params,
            timeout=60,
        )
        response.raise_for_status()
        try:
            payload: list[DepApiItem] = response.json()
        except json.JSONDecodeError as exception:
            message = "Unable to decode DEP API response"
            raise ValueError(message) from exception
        return payload
