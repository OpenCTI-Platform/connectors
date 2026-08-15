import re

import requests
from doppel_client.constants import DOPPEL_ATTRIBUTION_HEADERS
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl

VALID_QUEUE_STATES = {
    "doppel_review",
    "needs_confirmation",
    "actioned",
    "taken_down",
    "monitoring",
    "archived",
}
VALID_ENTITY_STATES = {
    "active",
    "down",
    "parked",
    "suspicious",
    "unclassified",
    "unrelated",
    "related",
    "unknown",
}
VALID_TAG_ACTIONS = {"add", "remove"}
VALID_FILE_ACTIONS = {"upload", "delete"}
MAX_FILES_PER_REQUEST = 10
DOPPEL_ALERT_ID_PATTERN = re.compile(r"[A-Za-z0-9]{1,3}-\d+")


class DoppelClientError(Exception):
    """Raised when a request to the Doppel API fails."""


class DoppelClient:
    """Thin client for the Doppel Brand Protection API."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: HttpUrl,
        api_key: str,
        user_api_key: str,
        organization_code: str | None = None,
    ):
        """
        Initialize the client with necessary configuration.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            base_url (HttpUrl): The Doppel API base URL.
            api_key (str): The Doppel API key (`x-api-key` header).
            user_api_key (str): The Doppel user API key (`x-user-api-key` header).
            organization_code (str | None): The Doppel organization workspace
                code (`x-organization-code` header), required for multi-org users.
        """
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")

        self.session = requests.Session()
        headers = {
            **DOPPEL_ATTRIBUTION_HEADERS,
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "x-user-api-key": user_api_key,
        }
        if organization_code:
            headers["x-organization-code"] = organization_code
        self.session.headers.update(headers)

    def create_alert(
        self, entity: str, entity_type: str, tags: list[str] | None = None
    ) -> dict:
        """
        Create an alert in Doppel for the given entity.

        :param entity: The observable value (URL or domain).
        :param entity_type: The Doppel entity type (e.g. "url" or "domain").
        :param tags: Optional list of tags to attach to the alert.
        :return: The created alert as a dict.
        """
        url = f"{self.base_url}/v1/alert"
        payload = {
            "entity": entity,
            "entity_type": entity_type,
            "tags": tags or [],
        }
        self.helper.connector_logger.info(
            "[API] Creating Doppel alert",
            {"url_path": url, "entity": entity, "entity_type": entity_type},
        )
        try:
            response = self.session.post(url, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, requests.HTTPError) as err:
            raise DoppelClientError(
                f"Failed to create Doppel alert for '{entity}': {err}"
            ) from err

    @staticmethod
    def _alert_selector(
        alert_id: str | None, entity: str | None
    ) -> tuple[dict[str, str], str]:
        """Validate and build a single-alert API selector."""
        if bool(alert_id) == bool(entity):
            raise ValueError("Exactly one of alert_id or entity must be provided")
        if alert_id and not DOPPEL_ALERT_ID_PATTERN.fullmatch(alert_id):
            raise ValueError(f"Invalid Doppel alert ID: {alert_id}")
        if entity is not None and not entity.strip():
            raise ValueError("entity must not be blank")
        return (
            ({"id": alert_id}, alert_id) if alert_id else ({"entity": entity}, entity)
        )

    @staticmethod
    def _validate_alert_response(
        alert: object,
        *,
        identifier: str,
        expected_alert_id: str | None = None,
    ) -> dict:
        """Validate that Doppel returned the selected alert."""
        if not isinstance(alert, dict):
            raise DoppelClientError(f"Invalid response for Doppel alert '{identifier}'")
        returned_alert_id = alert.get("id")
        if not isinstance(
            returned_alert_id, str
        ) or not DOPPEL_ALERT_ID_PATTERN.fullmatch(returned_alert_id):
            raise DoppelClientError(f"Invalid response for Doppel alert '{identifier}'")
        if expected_alert_id and returned_alert_id != expected_alert_id:
            raise DoppelClientError(
                f"Doppel returned the wrong alert for '{identifier}'"
            )
        return alert

    def get_alert(
        self,
        *,
        alert_id: str | None = None,
        entity: str | None = None,
    ) -> dict:
        """Retrieve the current state of one Doppel alert."""
        params, identifier = self._alert_selector(alert_id, entity)
        url = f"{self.base_url}/v1/alert"
        self.helper.connector_logger.info(
            "[API] Getting Doppel alert",
            {"url_path": url, "alert_identifier": identifier},
        )
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return self._validate_alert_response(
                response.json(),
                identifier=identifier,
                expected_alert_id=alert_id,
            )
        except (requests.RequestException, requests.HTTPError) as err:
            raise DoppelClientError(
                f"Failed to get Doppel alert '{identifier}': {err}"
            ) from err

    def update_alert(
        self,
        *,
        alert_id: str | None = None,
        entity: str | None = None,
        queue_state: str | None = None,
        entity_state: str | None = None,
        comment: str | None = None,
        tag_action: str | None = None,
        tag_name: str | None = None,
        file_action: str | None = None,
        files: list[dict] | None = None,
    ) -> dict:
        """
        Update an existing Doppel alert.

        Exactly one alert selector must be supplied. Paired tag and file fields are
        validated locally so malformed requests fail before reaching Doppel.

        :param alert_id: Doppel alert ID (preferred).
        :param entity: Alert entity fallback when an ID is unavailable.
        :param queue_state: New Doppel queue state.
        :param entity_state: New Doppel entity state.
        :param comment: Comment to append to the alert.
        :param tag_action: Tag operation ("add" or "remove").
        :param tag_name: Existing Doppel tag name.
        :param file_action: File operation ("upload" or "delete").
        :param files: File payloads accepted by the Update Alert API.
        :return: The updated alert as a dict.
        """
        params, identifier = self._alert_selector(alert_id, entity)
        if (tag_action is None) != (tag_name is None):
            raise ValueError("tag_action and tag_name must be provided together")
        if (file_action is None) != (files is None) or files == []:
            raise ValueError("file_action and files must be provided together")
        if queue_state is not None and queue_state not in VALID_QUEUE_STATES:
            raise ValueError(f"Invalid queue_state: {queue_state}")
        if entity_state is not None and entity_state not in VALID_ENTITY_STATES:
            raise ValueError(f"Invalid entity_state: {entity_state}")
        if comment is not None and not comment.strip():
            raise ValueError("comment must not be blank")
        if tag_action is not None and tag_action not in VALID_TAG_ACTIONS:
            raise ValueError(f"Invalid tag_action: {tag_action}")
        if tag_name is not None and not tag_name.strip():
            raise ValueError("tag_name must not be blank")
        if file_action is not None and file_action not in VALID_FILE_ACTIONS:
            raise ValueError(f"Invalid file_action: {file_action}")
        if files is not None:
            if not isinstance(files, list) or len(files) > MAX_FILES_PER_REQUEST:
                raise ValueError(
                    f"files must contain between 1 and {MAX_FILES_PER_REQUEST} items"
                )
            file_names = []
            for file in files:
                if not isinstance(file, dict):
                    raise ValueError("Each file must be an object")
                file_name = str(file.get("file_name") or "")
                if not file_name.strip():
                    raise ValueError("Each file must include a non-empty file_name")
                if (
                    file_name.startswith(".")
                    or ".." in file_name
                    or "\0" in file_name
                    or "/" in file_name
                    or "\\" in file_name
                ):
                    raise ValueError(f"Invalid file_name: {file_name}")
                if file_action == "upload" and not file.get("file_to_upload"):
                    raise ValueError("Each uploaded file must include file_to_upload")
                file_names.append(file_name)
            if len(file_names) != len(set(file_names)):
                raise ValueError("Duplicate file names are not allowed")

        payload = {
            key: value
            for key, value in {
                "queue_state": queue_state,
                "entity_state": entity_state,
                "comment": comment,
                "tag_action": tag_action,
                "tag_name": tag_name,
                "file_action": file_action,
                "files": files,
            }.items()
            if value is not None
        }
        if not payload:
            raise ValueError("At least one alert field must be provided")

        url = f"{self.base_url}/v1/alert"
        self.helper.connector_logger.info(
            "[API] Updating Doppel alert",
            {
                "url_path": url,
                "alert_identifier": identifier,
                "updated_fields": list(payload),
            },
        )
        try:
            response = self.session.put(url, params=params, json=payload, timeout=30)
            response.raise_for_status()
            if not response.content:
                raise DoppelClientError(
                    f"Invalid response for Doppel alert '{identifier}'"
                )
            return self._validate_alert_response(
                response.json(),
                identifier=identifier,
                expected_alert_id=alert_id,
            )
        except (requests.RequestException, requests.HTTPError) as err:
            raise DoppelClientError(
                f"Failed to update Doppel alert '{identifier}': {err}"
            ) from err

    def request_takedown(
        self,
        *,
        comment: str,
        alert_id: str | None = None,
        entity: str | None = None,
    ) -> dict:
        """
        Request a takedown for an existing alert by setting its queue state to "actioned".

        :param alert_id: Doppel alert ID (preferred).
        :param entity: Alert entity fallback when an ID is unavailable.
        :param comment: Comment attached to the takedown request.
        :return: The updated alert as a dict.
        """
        return self.update_alert(
            alert_id=alert_id,
            entity=entity,
            queue_state="actioned",
            comment=comment,
        )
