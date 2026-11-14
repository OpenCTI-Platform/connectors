"""MISP API client: attribute search, then retrieval of the matching events."""

from dataclasses import dataclass, field
from typing import Any

from connectors_sdk.exceptions.error import DataRetrievalError
from pymisp import PyMISP


@dataclass
class MispMatch:
    """A MISP event and the attributes of that event that matched the looked-up values."""

    event: dict[str, Any]
    attributes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def event_id(self) -> str:
        return str(self.event.get("id", ""))


class MispClient:
    """Thin wrapper around PyMISP for IOC-centric lookups."""

    def __init__(self, url: str, api_key: str, ssl_verify: bool = True) -> None:
        self._misp = PyMISP(url=url, key=api_key, ssl=ssl_verify)

    def search(self, values: list[str]) -> list[MispMatch]:
        """
        Look up values in MISP and return one match per event.

        Step 1: search the attributes whose value is exactly one of `values`.
        Step 2: fetch the full event of every distinct `event_id` found.

        :raises DataRetrievalError: if MISP cannot be queried.
        """
        attributes: dict[str, dict[str, Any]] = {}
        for value in values:
            for attribute in self._search_attributes(value):
                attributes.setdefault(str(attribute.get("id")), attribute)

        attributes_by_event: dict[str, list[dict[str, Any]]] = {}
        for attribute in attributes.values():
            event_id = str(attribute.get("event_id", ""))
            if event_id:
                attributes_by_event.setdefault(event_id, []).append(attribute)

        return [
            MispMatch(event=self._get_event(event_id), attributes=event_attributes)
            for event_id, event_attributes in attributes_by_event.items()
        ]

    def _search_attributes(self, value: str) -> list[dict[str, Any]]:
        try:
            response = self._misp.search(
                controller="attributes", value=value, pythonify=False
            )
        except Exception as err:
            raise DataRetrievalError("MISP attribute search failed") from err
        if not isinstance(response, dict) or "errors" in response:
            raise DataRetrievalError(f"MISP attribute search failed: {response}")
        return response.get("Attribute", [])

    def _get_event(self, event_id: str) -> dict[str, Any]:
        try:
            response = self._misp.get_event(event_id, pythonify=False)
        except Exception as err:
            raise DataRetrievalError(f"MISP event {event_id} retrieval failed") from err
        if not isinstance(response, dict) or "Event" not in response:
            raise DataRetrievalError(
                f"MISP event {event_id} retrieval failed: {response}"
            )
        return response["Event"]
