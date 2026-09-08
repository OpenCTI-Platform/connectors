"""EXAMPLE HTTP client -- illustrates how to talk to an external API.

.. important::
    Everything in this module is a **worked example**, not real code to
    keep. `TemplateClient`, the `https://api.example.com/v1` base URL,
    the `/reports`/`/cves` endpoints, and the `Report`/`CVE` models
    do not correspond to any real API -- they exist purely to show *how* a
    client for an external-import connector is typically structured.
    Delete or rewrite everything below to match the API your connector
    actually calls.

What this example demonstrates, and why it matters for your own connector:
    - How to isolate all networking concerns (base URL, auth headers,
      pagination, error handling) in one place, so the rest of the
      connector (the "processors", see `connector/data_processors/`)
      never has to deal with raw HTTP requests or raw JSON -- only
      validated, typed objects (see `template_client/models.py`).
    - Two different fetch patterns, because real-world APIs differ in how
      much data they return:
        - `get_reports`: fetches an entire collection in a single call.
          Use this style if your endpoint is small enough (e.g. a few
          hundred items) to reasonably fit in memory at once.
        - `iter_cves`: fetches data page by page, as a generator. Use
          this style whenever the endpoint can return a large or unbounded
          amount of data -- it keeps memory usage low and lets the
          processor checkpoint progress between pages (see
          `VulnerabilitiesProcessor`).
    - See the `TemplateClient` class docstring below for what
      `BaseClientApi` (from `connectors-sdk`) already provides out of
      the box.

TODO:
    - [ ] Rename `TemplateClient` (and this `template_client` package) to
        something specific to your API, e.g. `CyberThreatApiClient`.
    - [ ] Replace the hardcoded base URL with one read from your
        connector's settings (see `connector/settings.py`), so it is
        user-configurable rather than baked in.
    - [ ] Replace the `session_headers` property with whatever headers
        your API requires (bearer token, basic auth, custom header, etc.).
    - [ ] Delete `get_reports`/`iter_cves` and replace them with one
        method per real endpoint you need to call, picking whichever of
        the two patterns above matches how much data that endpoint
        returns.
    - [ ] Keep the "validate the response into a typed model" step
        (see `template_client/models.py`) for every method you add --
        it is what protects the rest of the connector from malformed API
        responses.
"""

from typing import Any, Generator

from connectors_sdk import ApiClientError, BaseClientApi
from template_client.models import CVE, Report


class TemplateClient(BaseClientApi):
    """EXAMPLE client -- rewrite entirely for your own API.

    This class and its two example methods (`get_reports`, `iter_cves`)
    only exist to demonstrate the non-paginated and paginated fetch
    patterns described in this module's docstring. Neither endpoint is
    real. Rename this class (and the `template_client` package) to match
    your connector/API's name, e.g. `CyberThreatApiClient`.

    Notes:
        `BaseClientApi` already provides, out of the box, everything
        below `self._get`/`self._paginate_offset`: a lazily-created
        `requests.Session`, automatic retries with backoff on 429/5xx,
        proactive rate limiting, and typed exceptions (e.g.
        `ApiClientError`) mapped from HTTP status codes. This subclass
        never touches any of that directly -- it only supplies the
        `session_headers` property (for authentication) and calls the
        inherited `_get`/`_paginate_offset` helpers from its own
        endpoint methods.
    """

    def __init__(self, api_key: str, logger):
        """Initialize the client with everything it needs to call the API.

        Args:
            api_key: The API key used to authenticate against the external API.
                Used to build the `Authorization` header for every request.
            logger: The connector's logger, used to record every request
                made and every error encountered. Reuse the same logger instance
                the connector uses, so all logs are consistent and centralized.

        Notes:
            Add any other constructor argument your API requires (e.g. a configurable base URL,
            a second credential, a tenant/organization id, proxy settings...).
        """
        super().__init__(base_url="https://api.example.com/v1")

        self._api_key = api_key
        self._logger = logger

    @property
    def session_headers(self) -> dict[str, str]:
        """Build the HTTP headers sent with every request.

        Returns:
            dict[str, str]: Headers attached to every request made through
            this client (`BaseClientApi` reads this property internally).

        TODO:
            - [ ] Replace the `Authorization` header with whatever scheme your API expects:
                a bearer token built from `self._api_key`, a custom header (e.g. `X-Api-Key`),
                or a Basic-Auth header.
            - [ ] Never log `self._api_key` or the dict returned here (credentials leakage).
        """
        return {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self._api_key,
        }

    def get_reports(self, params: dict[str, Any] | None = None) -> list[Report]:
        """EXAMPLE -- fetch an entire collection in one call (no pagination).

        This is one of two example fetch patterns in this file (see
        `iter_cves` for the paginated alternative). `/reports` is not a
        real endpoint -- copy the *shape* of this method for any of your
        own endpoints that return their full result set in a single
        response, and delete this method once you no longer need it as a
        reference.

        Args:
            params: Optional query parameters, e.g. a date filter
                (`updatedAfter`) to only fetch reports updated since the
                last run. Pass `None` to fetch everything.

        Returns:
            list[Report]: The reports returned by the API, already parsed
            and validated against the `Report` model (see`template_client/models.py`).
            A malformed API response raises a `pydantic.ValidationError` here,
            before any bad data reaches the rest of the connector.

        Raises:
            ApiClientError: If the HTTP request fails (network error,
                non-2xx response, etc.). The error is logged before being
                re-raised, so the caller can decide how to handle it.

        Notes:
            Use this non-paginated style only when you are confident the
            endpoint's full response comfortably fits in memory (e.g. at
            most a few hundred/thousand items). If your real endpoint can
            return a large or unbounded number of items, use the paginated
            pattern demonstrated by `iter_cves` below instead.
        """
        endpoint = "/reports"

        if params and params.get("updatedAfter"):
            params["updatedAfter"] = params["updatedAfter"].isoformat()

        try:
            data = self._get(endpoint, params=params)

            self._logger.info(
                "[API] HTTP Get Request to endpoint",
                {"endpoint": endpoint, "params": params},
            )

            # Validate response
            return [Report(**report) for report in data]
        except ApiClientError as err:
            self._logger.error(
                "[API] Error while fetching reports",
                {"endpoint": endpoint, "error": str(err)},
            )
            raise

    def iter_cves(
        self, params: dict[str, Any] | None = None
    ) -> Generator[list[CVE], None, None]:
        """EXAMPLE -- fetch a large/unbounded collection, page by page.

        This is the second of two example fetch patterns in this file (see
        `get_reports` above for the simpler, non-paginated alternative).
        `/cves` is not a real endpoint -- copy the *shape* of this method
        for any of your own endpoints that can return a large number of
        items, and delete this method once you no longer need it as a
        reference.

        Args:
            params: Optional query parameters, e.g. a date filter
                (`since`) and/or a `start_page` to resume a previously
                interrupted import. Pass `None` to fetch everything from
                the start.

        Yields:
            list[CVE]: One page of CVEs at a time, already parsed and
            validated against the `CVE` model. Yielding page by page (a
            generator), instead of returning one big list, keeps memory
            usage low for large collections.

        Raises:
            ApiClientError: If a request fails while fetching a page. The
                error is logged before being re-raised; the caller
                (`VulnerabilitiesProcessor`) is responsible for
                checkpointing the last successfully processed page so the
                import can resume from there.

        Notes:
            `self._paginate_offset` assumes paged-style pagination
            (`?page=0&per_page=100`). If your real API instead uses an
            opaque cursor/next-token, implement the pagination loop
            directly here instead of using `_paginate_offset`.
        """
        endpoint = "/cves"

        if params and params.get("since"):
            params["since"] = params["since"].isoformat()

        try:
            for cves_page in self._paginate_offset(endpoint, params=params):
                self._logger.info(
                    "[API] HTTP Get Request to endpoint",
                    {"endpoint": endpoint, "params": params},
                )
                # Validate response page by page.
                yield [CVE(**cve) for cve in cves_page]
        except ApiClientError as err:
            self._logger.error(
                "[API] Error while fetching CVEs",
                {"endpoint": endpoint, "error": str(err)},
            )
            raise
