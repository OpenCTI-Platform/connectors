"""IPQS client module."""

import re
from typing import Any, Dict, Optional

from pycti import OpenCTIConnectorHelper
from requests import Response, session
from requests.exceptions import ConnectTimeout, HTTPError, InvalidURL, ProxyError

from .constants import (
    EMAIL_ENRICH_FIELDS,
    IP_ENRICH_FIELDS,
    LEAK_PASSWORD,
    LEAK_USERNAME_OR_EMAIL,
    PHONE_ENRICH_FIELDS,
    URL_ENRICH_FIELDS,
)

# Default per-request timeout (seconds) applied to every HTTP call so a
# stuck Intel network does not block the worker indefinitely.
_HTTP_TIMEOUT_SECONDS = 30

# Lightweight email-shape detector used to pick the right ``leaked``
# endpoint for a User-Account observable.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class IPQSClient:
    """Thin wrapper around the IPQS HTTP API."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: str,
        api_key: str,
    ) -> None:
        """Initialise IPQS client.

        The API key is sent through the ``IPQS-KEY`` HTTP header for
        every endpoint — including the ``/leaked/...`` family — so the
        secret is never written to the URL (and therefore never ends up
        in HTTP access logs).
        """
        self.helper = helper
        self.url = base_url.rstrip("/")
        self.session = session()
        self.session.headers.update({"IPQS-KEY": api_key})

        # Field maps consumed by the enrichment workers.
        self.ip_enrich_fields = IP_ENRICH_FIELDS
        self.url_enrich_fields = URL_ENRICH_FIELDS
        self.email_enrich_fields = EMAIL_ENRICH_FIELDS
        self.phone_enrich_fields = PHONE_ENRICH_FIELDS

    # ------------------------------------------------------------------
    # GET (legacy IP / URL / Email / Phone enrichment)
    # ------------------------------------------------------------------
    def _query(
        self, url: str, params: Optional[Dict[str, Any]] = None
    ) -> Optional[Response]:
        """Issue a GET request and return the parsed JSON body."""
        try:
            response = self.session.get(
                url, params=params, timeout=_HTTP_TIMEOUT_SECONDS
            )
            data = response.json()
            if str(data.get("success")) != "True":
                self.helper.log_error(f"Error: {data.get('message')}")
                return None
            return data
        except (ConnectTimeout, ProxyError, InvalidURL) as error:
            self.helper.log_error(f"Error connecting to IPQS. Error: {error}")
            return None

    def get_ipqs_info(self, enrich_type: str, enrich_value: str):
        """Return the IPQS enrichment for the given observable value."""
        url = f"{self.url}/{enrich_type}"
        params = {enrich_type: enrich_value}
        try:
            return self._query(url, params)
        except HTTPError as error:
            self.helper.log_error(f"Error when requesting data from IPQS: {error}")
            raise

    # ------------------------------------------------------------------
    # POST (leaked credentials / passwords)
    # ------------------------------------------------------------------
    @staticmethod
    def looks_like_email(value: str) -> bool:
        """Return ``True`` when ``value`` looks like an email address."""
        return bool(_EMAIL_RE.fullmatch((value or "").strip()))

    def get_leaked_info(self, leak_endpoint: str, value: str):
        """Return the IPQS Darkweb-Leak enrichment for ``value``.

        ``leak_endpoint`` is one of
        :data:`~.constants.LEAK_USERNAME_OR_EMAIL` (when the
        User-Account observable carries an ``account_login``) or
        :data:`~.constants.LEAK_PASSWORD` (when it carries a
        ``credential``). The IPQS leak API expects different JSON keys
        depending on the kind of data being looked up:

        * ``email`` for an email-shaped account login;
        * ``username`` for any other login;
        * ``password`` for a credential.

        The API key is sent through the ``IPQS-KEY`` header inherited
        from the shared session — *never* as a path component, which
        would risk leaking the secret into HTTP access logs.
        """
        if leak_endpoint == LEAK_USERNAME_OR_EMAIL:
            query_kind = "email" if self.looks_like_email(value) else "username"
        elif leak_endpoint == LEAK_PASSWORD:
            query_kind = "password"
        else:
            raise ValueError(f"Unsupported leak endpoint: {leak_endpoint!r}")

        url = f"{self.url}/leaked/{query_kind}"
        try:
            response = self.session.post(
                url,
                json={query_kind: value},
                timeout=_HTTP_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()
        except (ConnectTimeout, ProxyError, InvalidURL, HTTPError) as exc:
            self.helper.log_error(f"Error connecting to IPQS leaked API: {exc}")
            return None

        if not data.get("success", False):
            self.helper.log_error(f"IPQS leaked API error: {data.get('message')}")
            return None
        return data
