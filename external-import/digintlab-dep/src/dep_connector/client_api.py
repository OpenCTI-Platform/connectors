import json
from typing import TypeAlias

import requests

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
        # Validate the Cognito response shape explicitly. The previous
        # ``auth_payload["AuthenticationResult"]["IdToken"]`` chain
        # would surface a Cognito error envelope (e.g.
        # ``{"__type": "NotAuthorizedException", "message": "..."}``)
        # as a bare ``KeyError`` / ``TypeError`` deep in the connector,
        # which is hard to debug. Fail fast at the client boundary
        # with a descriptive ``ValueError`` (matching what
        # ``fetch_raw`` already does on a non-list payload), and
        # include the unexpected top-level keys / error fields so the
        # operator can correlate against the Cognito error reference
        # without re-running with a debugger attached.
        try:
            auth_payload = response.json()
        except json.JSONDecodeError as exception:
            error = "Unable to decode authentication response"
            raise ValueError(error) from exception
        if not isinstance(auth_payload, dict):
            error = (
                "Authentication response is not a JSON object; "
                f"expected dict, got {type(auth_payload).__name__}"
            )
            raise ValueError(error)
        try:
            authentication_result = auth_payload["AuthenticationResult"]
            token = authentication_result["IdToken"]
        except (KeyError, TypeError) as exception:
            error_keys = sorted(auth_payload.keys())
            error_type = auth_payload.get("__type")
            error_message = auth_payload.get("message")
            error = (
                "Unable to retrieve IdToken from authentication response; "
                f"top-level keys: {error_keys}"
            )
            if error_type or error_message:
                error += f" (Cognito error: {error_type} - {error_message})"
            raise ValueError(error) from exception
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
            payload = response.json()
        except json.JSONDecodeError as exception:
            message = "Unable to decode DEP API response"
            raise ValueError(message) from exception

        # The DEP announcements endpoint returns a JSON array of objects;
        # validate the runtime shape explicitly so a future API change
        # that returns an error object (``{"message": "..."}``) or a
        # single-item dict surfaces as a clear ``ValueError`` at the
        # client boundary instead of crashing downstream when
        # ``LeakRecord(**raw_item)`` is fed a non-dict.
        if not isinstance(payload, list):
            error = (
                "DEP API returned a non-list payload; "
                f"expected list of items, got {type(payload).__name__}"
            )
            raise ValueError(error)
        for index, item in enumerate(payload):
            if not isinstance(item, dict):
                error = (
                    "DEP API returned a non-dict item at index "
                    f"{index}: {type(item).__name__}"
                )
                raise ValueError(error)
        return payload
