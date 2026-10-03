from collections.abc import Collection, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from falconpy import IOC as CrowdstrikeIOC
from falconpy import Alerts as CrowdstrikeAlerts

from .constants import (
    observable_type_mapper,
    platform_mapper,
    severity_mapper,
)

if TYPE_CHECKING:
    from crowdstrike_connector.settings import CrowdstrikeEndpointSecurityConfig
    from pycti import OpenCTIConnectorHelper

IOC_SOURCE = "OpenCTI IOC"
"""Source set on every IOC created by the connector."""

TO_DELETE_TAG = "TO_DELETE"
"""Tag added to the IOCs soft-deleted by the connector (permanent_delete=False)."""

IOC_PAGE_SIZE = 500
"""Page size of the IOC read-back (maximum accepted by the IOC API)."""

MAX_IOC_PAGES = 2_000
"""Safety bound of the IOC read-back (1 000 000 IOCs)."""

ALERT_PAGE_SIZE = 1_000
"""Page size of the alert retrieval (maximum accepted by the Alerts API)."""


def alert_id(alert: dict[str, Any]) -> str | None:
    """Return the id of an alert (``composite_id``, ``id`` for older payloads)."""
    identifier = alert.get("composite_id") or alert.get("id")
    return str(identifier) if identifier else None


class CrowdstrikeApiError(Exception):
    """Raised when the CrowdStrike API rejects a request."""


class IocOperationStatus(StrEnum):
    """Outcome of an IOC operation of the connector."""

    CREATED = "created"
    UPDATED = "updated"
    EXISTS = "exists"
    DELETED = "deleted"
    ABSENT = "absent"
    SKIPPED = "skipped"
    FAILED = "failed"


LIVE_STATUSES = frozenset(
    {IocOperationStatus.CREATED, IocOperationStatus.UPDATED, IocOperationStatus.EXISTS}
)
"""Outcomes meaning that the IOC is present in CrowdStrike after the operation."""


@dataclass(frozen=True, slots=True)
class IocOperationResult:
    """Outcome of a create, update or delete operation on a CrowdStrike IOC.

    Attributes:
        status: What happened (created, updated, already existing, deleted, absent
            from CrowdStrike, skipped because the IOC type is not supported, failed).
        ioc_id: The CrowdStrike IOC id, when known.
        error: The CrowdStrike error message, when the operation failed.
    """

    status: IocOperationStatus
    ioc_id: str | None = None
    error: str | None = None

    @property
    def is_live(self) -> bool:
        """Tell whether the IOC is present in CrowdStrike after the operation."""
        return self.status in LIVE_STATUSES


class CrowdstrikeClient:
    """
    Working with Falcon Py for Crowdstrike API call
    """

    def __init__(
        self,
        config: "CrowdstrikeEndpointSecurityConfig",
        helper: "OpenCTIConnectorHelper",
    ):
        self.helper = helper
        self.config = config
        self.cs = CrowdstrikeIOC(
            client_id=self.config.client_id,
            client_secret=self.config.client_secret.get_secret_value(),
            # Convert HttpUrl to string
            base_url=str(self.config.api_base_url),
        )
        self._alerts: CrowdstrikeAlerts | None = None

    @property
    def alerts(self) -> CrowdstrikeAlerts:
        """Alerts service class, sharing the authentication of the IOC service class."""
        if self._alerts is None:
            self._alerts = CrowdstrikeAlerts(auth_object=self.cs)
        return self._alerts

    @staticmethod
    def _api_error_message(response: dict) -> str | None:
        """
        Extract the error message of a Crowdstrike API response
        :param response: Response in dict
        :return: Error message, None when the call succeeded
        """
        status_code = response.get("status_code", 0)
        if status_code < 400:
            return None
        body = response.get("body") or {}
        for error in body.get("errors") or []:
            if isinstance(error, dict) and error.get("message"):
                return str(error["message"])
        return f"HTTP {status_code}"

    def _handle_api_error(self, response: dict) -> str | None:
        """
        Handle API error from Crowdstrike
        :param response: Response in dict
        :return: Error message, None when the call succeeded
        """
        error_message = self._api_error_message(response)
        if error_message is not None:
            self.helper.connector_logger.error(
                "[API] Error while processing indicator",
                {"error_message": error_message},
            )
        return error_message

    def _search_indicator_with_error(
        self, ioc_value: str
    ) -> tuple[list | None, str | None]:
        """
        Search for existing indicator into Crowdstrike
        :param ioc_value: IOC value in string
        :return: List of IOC ids (None on error) and the error message
        """
        try:
            cs_filter = f'value:"{ioc_value}"+created_by:"{self.config.client_id}"'

            response = self.cs.indicator_search(filter=cs_filter)
            error_message = self._handle_api_error(response)

            if response["status_code"] == 200:
                return response["body"]["resources"], None
            return None, error_message or (
                f"Unexpected status code {response['status_code']}"
            )

        except Exception as err:
            self.helper.connector_logger.error(
                "[API] Error while searching indicator", {"error_message": err}
            )
            return None, str(err) or type(err).__name__

    def _search_indicator(self, ioc_value: str) -> list | None:
        """
        Search for existing indicator into Crowdstrike
        If data exist, return the ID of the resource
        :param ioc_value: IOC value in string
        :return: List of resources or None
        """
        return self._search_indicator_with_error(ioc_value)[0]

    @staticmethod
    def _parse_indicator_pattern(pattern: str) -> str:
        """
        Parse the indicator pattern got from stream
        :param pattern: Pattern of IOC in string
        :return: String of pattern parsed
        """
        return pattern.strip("[]").split(" ")[0]

    @staticmethod
    def _extract_indicator_value(pattern: str) -> str:
        """
        Extract the indicator value got from stream data pattern
        :param pattern: Pattern of IOC in string
        :return: String of IOC value extracted
        """
        return pattern.strip("[]").split(" ")[2].replace("'", "")

    def _map_indicator_type(self, pattern: str) -> str | None:
        """
        Map the indicator main observable type in OpenCTI with Crowdstrike IOC type
        :param pattern: Pattern of IOC in string
        :return: Observable type in string or None no map
        """
        ioc_pattern_type = self._parse_indicator_pattern(pattern)

        for obs_type in observable_type_mapper:
            if obs_type == ioc_pattern_type:
                return observable_type_mapper[obs_type]

        # If OpenCTI observable type is not in Crowdstrike
        return None

    def _resolve_action(self, ioc_type: str) -> str:
        """
        Resolve the CrowdStrike action for a given IOC type based on config.
        Falls back to 'detect' for unknown IOC types not covered by the config.
        """
        action_map = {
            "ipv4": self.config.action_on_ip,
            "ipv6": self.config.action_on_ip,
            "domain": self.config.action_on_domain,
            "sha256": self.config.action_on_hash,
            "md5": self.config.action_on_hash,
        }
        action = action_map.get(ioc_type, "detect")
        return action

    def _map_severity(self, data: dict) -> str:
        """
        Map OpenCTI indicator score to severity value from Crowdstrike
        :param data: Data of IOC in dict
        :return: Severity value in string
        """
        indicator_score = self.helper.get_attribute_in_extension("score", data)

        for score_range in severity_mapper:
            if indicator_score in score_range:
                return severity_mapper[score_range]

    def _map_platform(self, data: dict) -> list | None:
        """
        Map OpenCTI indicator platforms to platform value from Crowdstrike
        :param data: Data of IOC in dict
        :return: List of platforms
        """
        indicator_platforms = self.helper.get_attribute_in_mitre_extension(
            "platforms", data
        )
        platforms = []

        # Only loop in available platforms, else continue
        for platform in platform_mapper:
            if indicator_platforms is not None and platform in indicator_platforms:
                if self.config.falcon_for_mobile_active:
                    platforms.append(platform_mapper[platform])
                elif platform not in ["ios", "android"]:
                    # If "Falcon for mobile" is not active in Crowdstrike
                    # API doesn't accept ["ios", "android"]
                    platforms.append(platform_mapper[platform])
                else:
                    self.helper.connector_logger.info(
                        "[API] Some value cannot be added or updated in Crowdstrike ",
                        {
                            "ioc_platforms_expected": ["windows", "mac", "linux"],
                            "ioc_platform_received": indicator_platforms,
                        },
                    )
                    continue

        if indicator_platforms is None:
            # If there is no platforms in OpenCTI
            # Add default platforms: "windows", "mac", "linux"
            platforms.extend(["windows", "mac", "linux"])

        if len(platforms) == 0:
            return None
        else:
            return platforms

    @staticmethod
    def _handle_labels(data: dict, event: str) -> None:
        """
        Handle labels in case permanent_delete configuration is False
        :param data: Data of IOC in dict
        :param event: Event in string
        :return: None
        """
        if event == "delete":
            if "labels" in data:
                labels = data["labels"]
                labels.append(TO_DELETE_TAG)
                data["labels"] = labels
            else:
                data["labels"] = [TO_DELETE_TAG]
        if event == "create":
            if "labels" in data:
                # Keep the new labels added, TO_DELETE is removed here
                labels = data["labels"]
                data["labels"] = labels
            else:
                # Remove TO_DELETE tag
                data["labels"] = []

    def _generate_indicator_body(
        self, data: dict, ioc_value: str, ioc_id: str = None
    ) -> dict | None:
        """
        Generate the body for Falcon Crowdstrike API call
        Required value: ioc_type, ioc_platforms, ioc_value
        :param data:
        :return: Body in dict or return None if required value is None
        """
        ioc_type = self._map_indicator_type(data["pattern"])

        # IOC type is required, return None if no type
        if ioc_type is not None:
            ioc_action = self._resolve_action(ioc_type)
            ioc_description = data.get("description", None)
            ioc_valid_until = data.get("valid_until", None)
            ioc_tags = data.get("labels", None)
            ioc_severity = self._map_severity(data)
            ioc_platforms = self._map_platform(data)

            indicator = {
                "action": ioc_action,
                "mobile_action": ioc_action,
                "type": ioc_type,
                "value": ioc_value,
                "severity": ioc_severity,
                "applied_globally": True,
                "source": IOC_SOURCE,
            }

            # If description exists, add it in indicator to create in Crowdstrike
            if ioc_id is not None:
                indicator["id"] = ioc_id

            # If description exists, add it in indicator to create in Crowdstrike
            if ioc_description is not None:
                indicator["description"] = ioc_description

            # If valid_until value exists, add it in indicator to create in Crowdstrike
            if ioc_valid_until is not None:
                indicator["expiration"] = ioc_valid_until

            # If tags exist, add it in indicator to create in Crowdstrike
            if ioc_tags is not None:
                indicator["tags"] = ioc_tags

            # If platforms is added, add it in indicator to create in Crowdstrike
            if ioc_platforms is not None:
                indicator["platforms"] = ioc_platforms

            body = {"comment": "IOC imported from OpenCTI", "indicators": [indicator]}

            return body
        else:
            return None

    @staticmethod
    def _created_ioc_id(response: dict) -> str | None:
        """
        Extract the id of the IOC created by an indicator_create call
        :param response: Response in dict
        :return: IOC id or None
        """
        for resource in (response.get("body") or {}).get("resources") or []:
            if isinstance(resource, dict) and resource.get("id"):
                return str(resource["id"])
        return None

    def create_indicator(
        self, data: dict, event: str | None = None
    ) -> IocOperationResult:
        """
        Create IOC from OpenCTI to Crowdstrike
        :param data: Data of IOC in dict
        :param event: Event in string or None
        :return: Outcome of the operation (CrowdStrike IOC id on success)
        """
        ioc_value = self._extract_indicator_value(data["pattern"])
        ioc_cs, search_error = self._search_indicator_with_error(ioc_value)

        # If IOC doesn't exist, create the IOC into Crowdstrike
        if ioc_cs is not None and len(ioc_cs) == 0:
            body = self._generate_indicator_body(data, ioc_value)

            if body is not None:
                response = self.cs.indicator_create(body=body)
                error_message = self._handle_api_error(response)

                if response["status_code"] == 201:
                    self.helper.connector_logger.info(
                        "[API] IOC successfully created in Crowdstrike",
                        {"ioc_value": ioc_value},
                    )
                    return IocOperationResult(
                        IocOperationStatus.CREATED,
                        ioc_id=self._created_ioc_id(response),
                    )
                return IocOperationResult(
                    IocOperationStatus.FAILED,
                    error=error_message
                    or f"Unexpected status code {response['status_code']}",
                )
            else:
                self.helper.connector_logger.info(
                    "[API] IOC cannot be created in Crowdstrike",
                    {"ioc_value": ioc_value},
                )
                return IocOperationResult(IocOperationStatus.SKIPPED)

        elif self.config.permanent_delete is False:
            result = self.update_indicator(data, event)

            self.helper.connector_logger.info(
                "[API] IOC already exists in Crowdstrike",
                {"ioc_value": ioc_value},
            )
            return result
        else:
            self.helper.connector_logger.info(
                "[API] IOC already exists in Crowdstrike",
                {"ioc_value": ioc_value},
            )
            if ioc_cs is None:
                return IocOperationResult(IocOperationStatus.FAILED, error=search_error)
            return IocOperationResult(IocOperationStatus.EXISTS, ioc_id=ioc_cs[0])

    def update_indicator(
        self, data: dict, event: str | None = None
    ) -> IocOperationResult:
        """
        Update IOC from OpenCTI to Crowdstrike
        :param data: Data of IOC in dict
        :param event: Event in string or None
        :return: Outcome of the operation (CrowdStrike IOC id on success)
        """
        ioc_value = self._extract_indicator_value(data["pattern"])
        ioc_cs, search_error = self._search_indicator_with_error(ioc_value)

        # If IOC exists, update the IOC into Crowdstrike
        if ioc_cs is not None and len(ioc_cs) != 0:
            # In case of permanent_delete is False
            # Update data with label TO_DELETE for Crowdstrike
            if self.config.permanent_delete is False:
                self._handle_labels(data, event)

            ioc_id = ioc_cs[0]
            body = self._generate_indicator_body(data, ioc_value, ioc_id)

            if body is not None:
                response = self.cs.indicator_update(body=body)
                error_message = self._handle_api_error(response)

                if response["status_code"] == 200:
                    self.helper.connector_logger.info(
                        "[API] IOC successfully updated in Crowdstrike",
                        {"ioc_value": ioc_value},
                    )
                    return IocOperationResult(IocOperationStatus.UPDATED, ioc_id=ioc_id)
                return IocOperationResult(
                    IocOperationStatus.FAILED,
                    ioc_id=ioc_id,
                    error=error_message
                    or f"Unexpected status code {response['status_code']}",
                )
            else:
                self.helper.connector_logger.info(
                    "[API] IOC cannot be updated in Crowdstrike",
                    {"ioc_value": ioc_value},
                )
                return IocOperationResult(IocOperationStatus.SKIPPED, ioc_id=ioc_id)

        else:
            self.helper.connector_logger.info(
                "[API] IOC doesn't exist in Crowdstrike",
                {"ioc_value": ioc_value},
            )
            if ioc_cs is None:
                return IocOperationResult(IocOperationStatus.FAILED, error=search_error)
            return IocOperationResult(IocOperationStatus.ABSENT)

    def delete_indicator(self, data: dict) -> IocOperationResult:
        """
        Delete IOC from OpenCTI to Crowdstrike
        :param data: Data of IOC in dict
        :return: Outcome of the operation (CrowdStrike IOC id on success)
        """
        ioc_value = self._extract_indicator_value(data["pattern"])
        ioc_cs, search_error = self._search_indicator_with_error(ioc_value)

        # If IOC exists and permanent_delete is True, delete the IOC into Crowdstrike
        if ioc_cs is not None and len(ioc_cs) != 0:
            ioc_id = ioc_cs[0]
            response = self.cs.indicator_delete(ioc_id)
            error_message = self._handle_api_error(response)

            if response["status_code"] == 200:
                self.helper.connector_logger.info(
                    "[API] IOC successfully deleted in Crowdstrike",
                    {"ioc_value": ioc_value},
                )
                return IocOperationResult(IocOperationStatus.DELETED, ioc_id=ioc_id)
            return IocOperationResult(
                IocOperationStatus.FAILED,
                ioc_id=ioc_id,
                error=error_message
                or f"Unexpected status code {response['status_code']}",
            )

        else:
            self.helper.connector_logger.info(
                "[API] IOC doesn't exist in Crowdstrike",
                {"ioc_value": ioc_value},
            )
            if ioc_cs is None:
                return IocOperationResult(IocOperationStatus.FAILED, error=search_error)
            return IocOperationResult(IocOperationStatus.ABSENT)

    def _raise_for_response(self, response: dict, expected_status: int) -> dict:
        """
        Raise when a Crowdstrike API response is not the expected one
        :param response: Response in dict
        :param expected_status: Expected HTTP status code
        :return: Response body in dict
        """
        if response.get("status_code") != expected_status:
            raise CrowdstrikeApiError(
                self._api_error_message(response)
                or f"Unexpected status code {response.get('status_code')}"
            )
        body = response.get("body")
        return body if isinstance(body, dict) else {}

    @staticmethod
    def _resources_of(body: dict[str, Any], kind: str) -> list[Any]:
        """
        Return the resources of a listing response
        :param body: Response body
        :param kind: What is listed, for the error message
        :return: The resources, empty only for a listing reported empty
        :raise CrowdstrikeApiError: When the response carries no resource list. It is
            never read as an empty listing: every deployment would look absent and
            the hit window would move past unread alerts
        """
        resources = body.get("resources")
        pagination = (body.get("meta") or {}).get("pagination") or {}
        if resources is None and pagination.get("total") == 0:
            return []
        if not isinstance(resources, list):
            raise CrowdstrikeApiError(
                f"Unexpected {kind} listing response (resources are missing)"
            )
        return resources

    def iter_connector_iocs(
        self, page_size: int = IOC_PAGE_SIZE, max_pages: int = MAX_IOC_PAGES
    ) -> Iterator[dict[str, Any]]:
        """
        Iterate over the IOCs created by the connector's API client
        (`created_by` is the API client id, as for the stream searches)
        :param page_size: Number of IOCs per page
        :param max_pages: Safety bound of the number of pages
        :return: IOC entities
        :raise CrowdstrikeApiError: On any API error, never yield a partial listing silently
        """
        after: str | None = None
        seen_tokens: set[str] = set()
        for _ in range(max_pages):
            parameters: dict[str, Any] = {
                "filter": f'created_by:"{self.config.client_id}"',
                "limit": page_size,
            }
            if after:
                parameters["after"] = after
            body = self._raise_for_response(
                self.cs.indicator_combined(parameters=parameters), 200
            )
            resources = self._resources_of(body, "IOC")
            for resource in resources:
                if isinstance(resource, dict):
                    yield resource
            pagination = (body.get("meta") or {}).get("pagination") or {}
            after = pagination.get("after")
            if not resources or not after:
                return
            if after in seen_tokens:
                raise CrowdstrikeApiError(
                    "The IOC API returned the same pagination token twice"
                )
            seen_tokens.add(after)
        raise CrowdstrikeApiError(
            f"IOC read-back stopped after {max_pages} pages without reaching the end"
        )

    def delete_ioc(self, ioc_id: str) -> None:
        """
        Delete one IOC by id
        :param ioc_id: CrowdStrike IOC id
        :raise CrowdstrikeApiError: When CrowdStrike refuses the deletion
        """
        self._raise_for_response(self.cs.indicator_delete(ids=[ioc_id]), 200)

    def deactivate_ioc(self, ioc: dict[str, Any]) -> None:
        """
        Stop the detection of an IOC without deleting it (permanent_delete=False):
        the action becomes 'no_action' and the TO_DELETE tag is added
        :param ioc: IOC entity as read back from CrowdStrike
        :raise CrowdstrikeApiError: When CrowdStrike refuses the update
        """
        tags = [tag for tag in ioc.get("tags") or [] if isinstance(tag, str)]
        if TO_DELETE_TAG not in tags:
            tags.append(TO_DELETE_TAG)
        body = {
            "comment": "IOC withdrawn from OpenCTI",
            "indicators": [
                {
                    "id": ioc["id"],
                    "action": "no_action",
                    "mobile_action": "no_action",
                    "tags": tags,
                }
            ],
        }
        self._raise_for_response(self.cs.indicator_update(body=body), 200)

    def iter_alerts(
        self,
        since: datetime,
        max_alerts: int,
        page_size: int = ALERT_PAGE_SIZE,
        exclude_ids: Collection[str] = (),
    ) -> Iterator[dict[str, Any]]:
        """
        Iterate over the alerts created since a date, oldest first
        :param since: Only return alerts created at or after this date
        :param max_alerts: Maximum number of alerts returned
        :param page_size: Number of alerts per page
        :param exclude_ids: Ids (see `alert_id`) of alerts already read, skipped
            without counting towards `max_alerts`
        :return: Alert entities
        :raise CrowdstrikeApiError: On any API error or an unexpected response
        """
        since_utc = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        after: str | None = None
        returned = 0
        while returned < max_alerts:
            body = self._raise_for_response(
                self.alerts.get_alerts_combined(
                    filter=f"created_timestamp:>='{since_utc}'",
                    sort="created_timestamp|asc",
                    limit=(
                        page_size
                        if exclude_ids
                        else min(page_size, max_alerts - returned)
                    ),
                    after=after,
                ),
                200,
            )
            resources = self._resources_of(body, "alert")
            for resource in resources:
                if returned >= max_alerts:
                    return
                if isinstance(resource, dict):
                    if exclude_ids and alert_id(resource) in exclude_ids:
                        continue
                    returned += 1
                    yield resource
            next_after = ((body.get("meta") or {}).get("pagination") or {}).get("after")
            if not resources or not next_after or next_after == after:
                return
            after = next_after
