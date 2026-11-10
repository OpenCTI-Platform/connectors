"""Client for the PolySwarm account endpoint (plan and quotas).

Endpoint: ``GET {api_url}/v3/public/accounts``. It is the call behind the
``polyswarm-api`` SDK's ``PolyswarmAPI.account_features()``; this connector
makes the request itself because it has no other use for the SDK.

Authentication is the raw API key in the ``Authorization`` header (no
``Bearer`` prefix). The body is ``{"result": {...}}``; the account number in
it is dropped here and never kept or logged.
"""

from types import SimpleNamespace
from typing import Any

from connectors_sdk import ApiClientError, BaseClientApi

ACCOUNT_PATH = "/v3/public/accounts"

# The only fields the quota reader uses.
_FIELDS = (
    "account_plan_name",
    "plan_period_start",
    "plan_period_end",
    "window_start",
    "window_end",
    "daily_api_limit",
    "daily_api_remaining",
    "is_trial",
    "is_trial_expired",
    "features",
)


class PolySwarmAccountClient(BaseClientApi):
    """Read-only client for the account plan and quotas."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        *,
        timeout: int = 30,
        max_retries: int = 1,
        backoff_factor: float = 1.0,
    ) -> None:
        super().__init__(
            api_url,
            timeout=timeout,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
        )
        if not api_key:
            raise ValueError("A PolySwarm API key is required")
        self._api_key = api_key

    @property
    def session_headers(self) -> dict[str, str]:
        return {"Authorization": self._api_key}

    def account_features(self) -> SimpleNamespace:
        """Return the account's plan and quotas as an attribute object.

        Raises:
            ApiClientError: On an HTTP error or an unexpected response.
        """
        body = self._get(ACCOUNT_PATH)
        result: Any = body.get("result") if isinstance(body, dict) else None
        if not isinstance(result, dict):
            raise ApiClientError(
                "Unexpected account response: expected a 'result' object"
            )
        return SimpleNamespace(**{name: result.get(name) for name in _FIELDS})
