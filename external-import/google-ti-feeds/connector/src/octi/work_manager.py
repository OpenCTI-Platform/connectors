"""The module will contain method to manage OpenCTI Works related tasks."""

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from logging import Logger

    from connector.src.octi.global_config import GlobalConfig
    from pycti import OpenCTIConnectorHelper as OctiHelper  # type: ignore

LOG_PREFIX = "[Work Manager]"


class WorkManager:
    """The class will contains method to manage OpenCTI Works related tasks."""

    def __init__(
        self,
        config: "GlobalConfig",
        helper: "OctiHelper",
        logger: Optional["Logger"] = None,
    ) -> None:
        """Initialize the WorkManager class.

        Args:
            config (dict): The configuration dictionary.
            helper (Helper): The helper object.
            logger (logging.Logger): The logger object.

        """
        self._config = config
        self._helper = helper
        self._logger = logger or logging.getLogger(__name__)
        self._current_work_id: Optional[str] = None

    def get_state(self) -> Dict[str, Any]:
        """Get the current state dict of the Connector.

        Returns:
            dict: The current state of the Connector.

        """
        self._helper.force_ping()
        return self._helper.get_state() or {}

    @staticmethod
    def _is_valid_iso_format(date_string: str) -> bool:
        """Check if a string is a valid ISO format date.

        Args:
            date_string (str): The date string to check

        Returns:
            bool: True if valid ISO format, False otherwise

        """
        try:
            datetime.fromisoformat(date_string.replace("Z", "+00:00"))
            return True
        except ValueError:
            return False

    def get_current_work_id(self) -> Optional[str]:
        """Get the current work ID.

        Returns:
            Optional[str]: The current work ID or None if no work is currently active.

        """
        return self._current_work_id

    def set_current_work_id(self, work_id: str) -> None:
        """Set the current work ID.

        Args:
            work_id (str): The work ID to set as current.

        """
        self._current_work_id = work_id
        self._logger.info(f"{LOG_PREFIX} Current work ID set to {work_id}")

    def update_state(
        self, state_key: str, date_str: str = "", error_flag: bool = False
    ) -> None:
        """Update the state of the connector.

        Args:
            error_flag (bool): Whether the work finished in error.
            state_key (str): The key of the state to update.
            date_str (str, optional): The date string. Defaults to "".

        """
        if not error_flag:
            current_state = self.get_state()
            now = datetime.now(timezone.utc).isoformat()
            if date_str != "" and isinstance(date_str, str):
                if self._is_valid_iso_format(date_str):
                    now = date_str
                elif "T" not in date_str or not ("+" in date_str or "Z" in date_str):
                    parsed_date = datetime.fromisoformat(
                        date_str.replace("Z", "+00:00")
                    )
                    now = parsed_date.isoformat()
            current_state[state_key] = now
            self._helper.set_state(state=current_state)
            self._helper.force_ping()
            self._logger.info(f"{LOG_PREFIX} Updated state for {state_key} to {now}")

    def initiate_work(self, name: str, work_counter: Optional[int] = None) -> str:
        """Initiate a new work for the Connector.

        Args:
            name (str): The name of the work.
            work_counter (Optional[int]): The counter for the work.

        Returns:
            str: The ID of the initiated work.

        """
        if work_counter is not None:
            name = f"{name} #({work_counter})"
        work_id: str = self._helper.api.work.initiate_work(
            self._helper.connect_id, name
        )
        self._current_work_id = work_id
        self._logger.info(f"{LOG_PREFIX} Initiated work {work_id} for {name}")
        return work_id

    def work_to_process(
        self,
        work_id: str,
        error_flag: bool = False,
        error_message: Optional[str] = None,
    ) -> None:
        """Work to process.

        Args:
            work_id (str): The ID of the work.
            error_flag (bool): Whether the work finished in error.
            error_message (Optional[str]): Specific error message to report. Defaults to None.

        """
        message = "Connector's work finished gracefully"
        if error_flag and error_message:
            message = f"Error: {error_message}"

        self._helper.api.work.to_processed(
            work_id=work_id,
            message=message,
            in_error=error_flag,
        )
        if self._current_work_id == work_id:
            self._current_work_id = None
        self._logger.info(f"{LOG_PREFIX} Work {work_id} marked to be processed")

    def process_all_remaining_works(
        self, error_flag: bool = False, error_message: Optional[str] = None
    ) -> None:
        """Process all remaining works and update the state.

        Args:
            error_flag (bool): Whether the work finished in error.
            error_message (Optional[str]): Specific error message to report. Defaults to None.

        """
        works = self._helper.api.work.get_connector_works(
            connector_id=self._helper.connect_id
        )
        for work in works:
            if work["status"] != "complete":
                self.work_to_process(
                    work_id=work["id"],
                    error_flag=error_flag,
                    error_message=error_message,
                )
        self._current_work_id = None
        self._logger.info(f"{LOG_PREFIX} All remaining works marked to be process.")

    def send_bundle(self, work_id: str, bundle: Any) -> None:
        """Send a bundle to OpenCTI.

        Args:
            work_id (str): The ID of the work.
            bundle (dict): The bundle to send.

        """
        bundle_json = self._helper.stix2_create_bundle(bundle)
        bundles_sent = self._helper.send_stix2_bundle(
            bundle=bundle_json,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )
        self._logger.info(
            f"{LOG_PREFIX} STIX objects sent to OpenCTI queue.",
            {"bundles_sent": str(len(bundles_sent))},
        )
