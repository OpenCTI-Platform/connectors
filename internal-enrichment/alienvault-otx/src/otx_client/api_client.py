from typing import Any
from urllib.parse import quote

import requests
from connectors_sdk import ApiClientError, ApiNotFoundError, BaseClientApi
from connectors_sdk.exceptions.error import DataRetrievalError
from otx_client.models import OtxGeneral
from pydantic import SecretStr, ValidationError

# OTX can be slow: the SDK retries a timed-out GET, so a stuck OTX costs several times this
REQUEST_TIMEOUT = 60

# OTX section of each supported entity type, as used in `/api/v1/indicators/<section>/...`
OTX_SECTIONS = {"IPv4-Addr": "IPv4", "Domain-Name": "domain", "Url": "url"}

# OTX files subdomains (`www.example.com`) under `hostname`, not `domain`: it is queried
# as a fallback for a domain name, so it is not the section of any entity type
OTX_HOSTNAME_SECTION = "hostname"

# Every section `OtxClient.get_general` accepts
ALLOWED_SECTIONS = frozenset({*OTX_SECTIONS.values(), OTX_HOSTNAME_SECTION})


class _RedirectError(requests.RequestException):
    """OTX answered with a redirect, which is never followed."""


class OtxClient(BaseClientApi):
    """Client for the AlienVault OTX DirectConnect API (`/api/v1/indicators`).

    Transient errors (408, 429, 5xx, timeouts) are retried by `BaseClientApi`, which
    honours the `Retry-After` header.
    """

    def __init__(
        self,
        base_url: str,
        api_key: SecretStr,
        timeout: float = REQUEST_TIMEOUT,
    ) -> None:
        self._api_key = api_key
        super().__init__(base_url, timeout=timeout)

    @property
    def session_headers(self) -> dict[str, str]:
        return {"X-OTX-API-KEY": self._api_key.get_secret_value()}

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send the request without following redirects.

        A redirect would forward the `X-OTX-API-KEY` header to the target host, so a
        3xx answer is an error instead.
        """
        kwargs["allow_redirects"] = False
        response = super()._raw_request(method, path, **kwargs)
        if 300 <= response.status_code < 400:
            raise _RedirectError(
                f"OTX answered with a redirect (HTTP {response.status_code}), "
                "which is not followed"
            )
        return response

    def get_general(self, section: str, value: str) -> OtxGeneral | None:
        """Return the `general` section of an indicator.

        Args:
            section: OTX section of the indicator: `IPv4`, `domain`, `hostname` or
                `url` (see `ALLOWED_SECTIONS`).
            value: The indicator, as stored in OpenCTI.

        Returns:
            The `general` section, `None` when OTX has no such indicator (HTTP 404)
            or rejects the value (HTTP 400, e.g. a private IP or an invalid domain).
            An indicator OTX does not know about the pulses of is not a 404: it is a
            `general` section with `pulse_info.count` at 0.

        Raises:
            ValueError: On a section that is not in `ALLOWED_SECTIONS`.
            DataRetrievalError: On any other HTTP error (401, 403, 429 or 5xx after
                the retries), on a redirect (never followed), on a network failure or
                timeout, and when the response is not a valid `general` section.
        """
        if section not in ALLOWED_SECTIONS:
            raise ValueError(f"Unsupported OTX section: {section}")
        path = f"/api/v1/indicators/{section}/{quote(value, safe='')}/general"
        try:
            body = self._get(path)
        except ApiNotFoundError:
            return None
        except ApiClientError as err:
            if err.status_code == 400:
                self.logger.warning(
                    "OTX rejected the indicator",
                    meta={
                        "section": section,
                        "value": value,
                        "detail": self._error_detail(err.response_body),
                    },
                )
                return None
            raise DataRetrievalError(
                f"Failed to fetch the OTX {section} {value}: {err}"
            ) from err
        except requests.RequestException as err:
            raise DataRetrievalError(
                f"Failed to fetch the OTX {section} {value}: {err}"
            ) from err
        try:
            return OtxGeneral.model_validate(body)
        except ValidationError as err:
            raise DataRetrievalError(
                f"OTX returned an invalid general section for {section} {value}: {err}"
            ) from err

    @staticmethod
    def _error_detail(response_body: Any) -> str | None:
        """Return the `detail` message of an OTX error body, if there is one."""
        if isinstance(response_body, dict):
            detail = response_body.get("detail")
            if isinstance(detail, str):
                return detail
        return None
