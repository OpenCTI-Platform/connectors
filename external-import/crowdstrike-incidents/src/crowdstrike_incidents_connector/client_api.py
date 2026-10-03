import requests
from falconpy import Alerts, Incidents


class CrowdstrikeApiError(Exception):
    """
    Raised when the CrowdStrike Falcon API returns an error response.

    It carries the HTTP status code and the CrowdStrike trace id so that the
    error can be reported to CrowdStrike support if needed.
    """

    def __init__(self, message: str, status_code=None, trace_id=None):
        self.status_code = status_code
        self.trace_id = trace_id
        super().__init__(message)


class ConnectorClient:
    # Max results per `/alerts/queries/alerts/v2` call (API max: 10000)
    ALERTS_QUERY_LIMIT = 1000
    # Max composite ids per `/alerts/entities/alerts/v2` call
    ALERTS_ENTITY_BATCH_SIZE = 1000
    # The alerts query endpoint refuses offsets above this value
    ALERTS_OFFSET_CEILING = 10000
    # Date field used for both the incremental filter and the sort
    ALERTS_DATE_FIELD = "updated_timestamp"

    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # `base_url` must match the CrowdStrike cloud region of the tenant
        # (us-1, us-2, eu-1, us-gov-1). When not set, FalconPy defaults to us-1,
        # which is a frequent cause of 403/404 responses.
        auth = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        if getattr(self.config, "base_url", None):
            auth["base_url"] = self.config.base_url

        self.falcon_incidents = Incidents(**auth)
        self.falcon_alerts = Alerts(**auth)

    @staticmethod
    def _extract_errors(body: dict) -> list:
        """
        Normalize the `errors` list returned by the Falcon API
        :param body: Body of the FalconPy response
        :return: List of error messages
        """
        errors = []
        for error in body.get("errors") or []:
            if isinstance(error, dict):
                errors.append(
                    f"{error.get('code', 'unknown code')}: "
                    f"{error.get('message', 'no message')}"
                )
            else:
                errors.append(str(error))
        return errors

    def _check_response(self, result, operation: str) -> dict:
        """
        Validate a FalconPy response and return its body.

        FalconPy never raises on HTTP errors: it returns a dict shaped as
        {"status_code": ..., "headers": ..., "body": {"errors": [...], "meta": {...}}}.
        This method turns any error response into a `CrowdstrikeApiError` so the
        caller (and ultimately the connector) can stop cleanly instead of
        crashing on a missing key.

        :param result: Raw response returned by a FalconPy method
        :param operation: Name of the called operation, used for logging
        :return: The `body` part of the response
        """
        if not isinstance(result, dict):
            raise CrowdstrikeApiError(
                f"[API] Unexpected response type for '{operation}': {type(result)}"
            )

        status_code = result.get("status_code")
        body = result.get("body") or {}
        trace_id = (body.get("meta") or {}).get("trace_id") or result.get(
            "headers", {}
        ).get("X-Cs-Traceid")
        errors = self._extract_errors(body)

        if errors or status_code is None or int(status_code) >= 400:
            error_msg = (
                f"[API] CrowdStrike API error while calling '{operation}' "
                f"(status code: {status_code}, trace id: {trace_id}): "
                f"{'; '.join(errors) if errors else 'no error detail returned'}"
            )
            self.helper.connector_logger.error(
                "[API] CrowdStrike API returned an error response",
                {
                    "operation": operation,
                    "status_code": status_code,
                    "trace_id": trace_id,
                    "errors": errors,
                },
            )
            raise CrowdstrikeApiError(
                error_msg, status_code=status_code, trace_id=trace_id
            )

        return body

    def _build_alerts_filter(self, since=None) -> str:
        """
        Build the FQL filter used to query alerts
        :param since: ISO-8601 timestamp, only alerts updated after it are returned
        :return: FQL filter as a string
        """
        filters = []
        if since:
            filters.append(f"{self.ALERTS_DATE_FIELD}:>'{since}'")
        extra_filter = getattr(self.config, "alert_filter", None)
        if extra_filter:
            filters.append(f"({extra_filter})")
        return "+".join(filters)

    def iter_alerts(self, since=None):
        """
        Yield the alerts updated after a given date, page by page, each page
        ordered by ascending `updated_timestamp`.

        Alerts are streamed instead of returned as a whole list so the caller
        can convert and publish them as they arrive, and keep its state cursor
        moving forward during the collection.

        `/alerts/queries/alerts/v2` caps offset pagination at 10 000 results, so
        once that ceiling is reached the time window is rolled forward using the
        last known timestamp instead of increasing the offset.

        :param since: ISO-8601 timestamp, only alerts updated after it are returned
        :return: Generator of lists of alert dicts
        """
        if not since:
            self.helper.connector_logger.warning(
                "[API] No start date provided, every alert of the tenant will be "
                "collected. Set `import_start_date` to limit the first run."
            )

        seen_ids = set()
        window_start = since
        offset = 0

        while True:
            params = {
                "filter": self._build_alerts_filter(window_start),
                "sort": f"{self.ALERTS_DATE_FIELD}|asc",
                "limit": self.ALERTS_QUERY_LIMIT,
                "offset": offset,
                "include_hidden": bool(
                    getattr(self.config, "alert_include_hidden", False)
                ),
            }
            if not params["filter"]:
                params.pop("filter")

            result = self.falcon_alerts.query_alerts_v2(**params)
            body = self._check_response(result, "query_alerts_v2")

            resources = body.get("resources") or []
            total = ((body.get("meta") or {}).get("pagination") or {}).get("total")

            self.helper.connector_logger.info(
                "[API] Querying alert ids",
                {
                    "offset": offset,
                    "retrieved": len(resources),
                    "total_for_window": total,
                },
            )

            new_ids = [i for i in resources if i not in seen_ids]
            seen_ids.update(new_ids)

            last_timestamp = None
            if new_ids:
                alerts = self.get_alert_details(new_ids)
                # The entity endpoint does not guarantee the order within a
                # batch, and the caller relies on it to move its cursor forward
                alerts.sort(key=lambda alert: alert.get(self.ALERTS_DATE_FIELD) or "")
                if alerts:
                    last_timestamp = alerts[-1].get(self.ALERTS_DATE_FIELD)
                yield alerts

            if not resources:
                break
            if not new_ids and offset == 0:
                # The rolled window only returns already known alerts
                break
            if len(resources) < self.ALERTS_QUERY_LIMIT:
                # Last page of the current window
                break

            offset += len(resources)

            if total is not None and offset >= total:
                break
            if offset >= self.ALERTS_OFFSET_CEILING:
                if not last_timestamp:
                    self.helper.connector_logger.warning(
                        "[API] Alert pagination ceiling reached and the window "
                        "could not be rolled forward, stopping the collection",
                        {"offset": offset},
                    )
                    break
                window_start = last_timestamp
                offset = 0

    def get_alert_details(self, composite_ids: list) -> list:
        """
        Retrieve the full alert entities for a list of composite ids, by batch
        :param composite_ids: List of alert composite ids
        :return: List of alert dicts
        """
        alerts = []
        for index in range(0, len(composite_ids), self.ALERTS_ENTITY_BATCH_SIZE):
            batch = composite_ids[index : index + self.ALERTS_ENTITY_BATCH_SIZE]
            result = self.falcon_alerts.get_alerts_v2(composite_ids=batch)
            body = self._check_response(result, "get_alerts_v2")
            resources = body.get("resources") or []

            self.helper.connector_logger.debug(
                "[API] Alert details retrieved",
                {"batch_size": len(batch), "retrieved": len(resources)},
            )
            alerts.extend(resources)
        return alerts

