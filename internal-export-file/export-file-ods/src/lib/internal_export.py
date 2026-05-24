"""Base class for the ODS export connector.

This module hosts the small piece of glue that wires a connector subclass to
the :class:`OpenCTIConnectorHelper`. Configuration is loaded from
``config.yml`` (next to ``main.py``) when present, so the connector can be
started either via Docker (configuration via environment variables) or as a
plain Python process (configuration via ``config.yml``).
"""

import os
from typing import Any, Dict

import yaml
from pycti import OpenCTIConnectorHelper


class InternalExportConnector:
    """Specific internal-export connector.

    This class encapsulates the main actions, expected to be run by any
    internal-export connector. The attributes defined below are complemented
    by each concrete connector subclass.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper used to communicate with
            the OpenCTI platform.
    """

    def __init__(self) -> None:
        self.helper = OpenCTIConnectorHelper(self._load_config())

    @staticmethod
    def _load_config() -> Dict[str, Any]:
        """Return the connector configuration.

        When a ``config.yml`` file is present alongside ``main.py`` it is
        loaded with :func:`yaml.safe_load`. Otherwise an empty dictionary is
        returned and :class:`OpenCTIConnectorHelper` falls back to reading
        environment variables.
        """
        # ``main.py`` and ``config.yml`` live in the same directory.
        config_file_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config.yml",
        )
        if not os.path.isfile(config_file_path):
            return {}
        with open(config_file_path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    def _process_message(self, data: Dict[str, Any]) -> str:
        """Process an export request.

        Args:
            data: Payload of the export request as documented in
                https://docs.opencti.io/latest/development/connectors/.
        """
        raise NotImplementedError

    def start(self) -> None:
        """Start the main loop."""
        self.helper.listen(self._process_message)
