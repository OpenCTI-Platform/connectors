# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike importer module."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import stix2
from pycti import OpenCTIConnectorHelper  # type: ignore


class BaseImporter(ABC):
    """CrowdStrike importer module."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        tlp_marking: stix2.MarkingDefinition,
        update_existing_data: bool,
    ) -> None:
        """Initialize CrowdStrike importer module."""
        self.helper = helper
        self.author = author
        self.tlp_marking = tlp_marking
        self.update_existing_data = update_existing_data

        self.work_id: Optional[str] = None

    def start(self, work_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Start import.

        :param work_id: Work identifier for current import process.
        :type work_id: str
        :param state: Current state of the importer.
        :type state: Dict[str, Any]
        :return: State after the import.
        :rtype: Dict[str, Any]
        """
        self.work_id = work_id

        return self.run(state)

    @abstractmethod
    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run import.

        :param state: Current state of the importer.
        :type state: Dict[str, Any]
        :return: State after the import.
        :rtype: Dict[str, Any]
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

    def _set_state(self, state: Dict[str, Any]) -> None:
        self.helper.set_state(state)

    def _send_bundle(self, bundle: stix2.Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(
            serialized_bundle,
            work_id=self.work_id,
            update=self.update_existing_data,
            bypass_split=True,
        )
