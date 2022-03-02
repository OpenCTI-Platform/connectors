"""Kaspersky importer module."""

from abc import ABC, abstractmethod
from typing import Any, Mapping, Optional

from pycti import OpenCTIConnectorHelper  # type: ignore

from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore

from kaspersky.client import KasperskyClient


class BaseImporter(ABC):
    """Kaspersky base importer."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: KasperskyClient,
        author: Identity,
        tlp_marking: MarkingDefinition,
        update_existing_data: bool,
    ) -> None:
        """Initialize Kaspersky base importer."""
        self.helper = helper
        self.client = client
        self.author = author
        self.tlp_marking = tlp_marking
        self.update_existing_data = update_existing_data

        self.work_id: Optional[str] = None

    def start(self, work_id: str, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """
        Start import.

        :param work_id: Work identifier for current import process.
        :type work_id: str
        :param state: Current state of the importer.
        :type state: Mapping[str, Any]
        :return: State after the import.
        :rtype: Mapping[str, Any]
        """
        self.work_id = work_id

        return self.run(state)

    @abstractmethod
    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """
        Run import.

        :param state: Current state of the importer.
        :type state: Mapping[str, Any]
        :return: State after the import.
        :rtype: Mapping[str, Any]
        """
        ...

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

    def _source_name(self) -> str:
        return self.author["name"]

    def _confidence_level(self) -> int:
        return self.helper.connect_confidence_level

    def _send_bundle(self, bundle: Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(
            serialized_bundle, work_id=self.work_id, update=self.update_existing_data
        )
