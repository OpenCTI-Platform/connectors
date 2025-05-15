"""The module will contains method to manage OpenCTI Works related tasks."""

import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from logging import Logger

    from connector.src.octi.global_config import GlobalConfig
    from pycti import OpenCTIConnectorHelper as OctiHelper  # type: ignore

class WorkManager:
    """The class will contains method to manage OpenCTI Works related tasks."""

    def __init__(self, config: "GlobalConfig", helper: "OctiHelper", logger: Optional["Logger"] = None) -> None:
        """Initialize the WorkManager class.

        Args:
            config (dict): The configuration dictionary.
            helper (Helper): The helper object.
            logger (logging.Logger): The logger object.

        """
        self._config = config
        self._helper = helper
        self._logger = logger or logging.getLogger(__name__)

    def get_state(self) -> Dict[str, Any]:
        """Get the current state dict of the Connector.

        Returns:
            dict: The current state of the Connector.

        """
        self._helper.force_ping()
        return self._helper.get_state() or {}

    def set_state(self) -> None:
        ...

    def update_state(self) -> None:
        ...

    def initiate_work(self) -> None:
        ...

    def _mark_work_processed(self) -> None:
        ...

    def finalize_work(self) -> None:
        ...

    def finalize_all_remaining_works(self):
        ...

    def wait_for_ingestion_completion(self) -> None:
        ...
