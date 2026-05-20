from typing import TYPE_CHECKING

from falconpy import Intel as CrowdstrikeIntel

if TYPE_CHECKING:
    from crowdstrike_feeds_connector import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class BaseCrowdstrikeClient:
    """
    Working with FalconPy library
    """

    def __init__(self, config: "ConnectorSettings", helper: "OpenCTIConnectorHelper"):
        """
        Initialize API with necessary configurations
        :param helper: Helper OpenCTI
        """
        self.config = config
        self.helper = helper
        self.cs_intel = CrowdstrikeIntel(
            client_id=self.config.crowdstrike.client_id.get_secret_value(),
            client_secret=self.config.crowdstrike.client_secret.get_secret_value(),
            base_url=str(self.config.crowdstrike.base_url),
        )

    def handle_api_error(self, response: dict) -> None:
        """
        Handle API error from Crowdstrike
        :param response: Response in dict
        :return: None
        """

        status_code = response.get("status_code")
        if status_code is None or status_code < 400:
            return

        # ``response["body"]["errors"][0]["message"]`` is not guaranteed:
        # a 403 can return an empty body, ``errors`` can be missing /
        # ``None`` / ``[]`` (the upstream sometimes reports a generic
        # failure without a specific item), and the first entry can be
        # a non-dict. Unpack defensively here so a secondary
        # ``IndexError`` / ``KeyError`` / ``TypeError`` cannot mask the
        # real status-code diagnostic before the caller (e.g.
        # ``_get_related_iocs``) gets a chance to handle the failure
        # gracefully.
        body = response.get("body") or {}
        errors = body.get("errors") or []
        first_error = errors[0] if errors else {}
        error_message = (
            first_error.get("message") if isinstance(first_error, dict) else None
        ) or "no error message returned by CrowdStrike API"

        if status_code == 403:
            self.helper.connector_logger.warning(
                "[API] Permission denied accessing resource",
                {"error_message": error_message, "status_code": status_code},
            )
        else:
            self.helper.connector_logger.error(
                "[API] Error while querying CrowdStrike API",
                {"error_message": error_message, "status_code": status_code},
            )
