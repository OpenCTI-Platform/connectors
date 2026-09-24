import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any, Mapping

from censys_enrichmentapis.builder import CensysStixBuilder
from censys_enrichmentapis.client import Client
from connectors_sdk.models import BaseObject

# ``observable`` arrives at the converters in two shapes: a plain
# ``dict`` from the OpenCTI enrichment payload (see
# ``Connector._process``) or a ``stix2`` object when a caller already
# has one (as in converter unit tests). Both shapes
# expose the read-only ``observable["..."]`` / ``.get(...)`` access
# pattern the converters rely on, so the contract is "any
# string-keyed mapping" rather than ``dict`` specifically — using
# ``Mapping[str, Any]`` lets static type checkers (mypy, pyright)
# accept the ``stix2`` callers without unsafe casts and also makes
# the read-only intent explicit at the API surface.
ObservableLike = Mapping[str, Any]


class CensysConverter(ABC):
    def __init__(self) -> None:
        self.builder = CensysStixBuilder()
        self.client: Client | None = None
        self.primary_observable_labels: list[str] = []

    def to_stix(
        self,
        observable: ObservableLike,
        data: Any | None = None,
        marking_refs: list[str] | None = None,
    ) -> list[BaseObject]:
        """Return the STIX bundle for *observable*.

        If *data* is provided, skip the API fetch and convert it directly —
        useful for tests and for callers that already have the payload.
        """
        if marking_refs is None:
            observable_marking_refs = observable.get("object_marking_refs")
            if observable_marking_refs:
                marking_refs = list(observable_marking_refs)
        self.builder.reset(marking_refs=marking_refs)
        self.primary_observable_labels = []
        if data is None:
            data = self._fetch_data(observable=observable)
        self._convert(observable=observable, data=data)
        return self.builder.bundle

    def _require_client(self) -> Client:
        if self.client is None:
            raise ValueError("Client is required")
        return self.client

    @staticmethod
    def _value(value: object, field: str) -> object | None:
        if isinstance(value, dict):
            return value.get(field)
        return getattr(value, field, None)

    @classmethod
    def _format_censys_labels(
        cls, values: Iterable[object], category: str | None = None
    ) -> list[str]:
        """Format and deduplicate Censys values as observable labels."""
        prefix = f"Censys_{category}_" if category else "Censys_"
        return list(
            dict.fromkeys(
                f"{prefix}{re.sub(r'[\s\-]+', '_', value.strip())}"
                for value in values
                if isinstance(value, str) and value.strip()
            )
        )

    @abstractmethod
    def _fetch_data(self, observable: ObservableLike) -> Any:
        """Fetch data required for STIX conversion."""

    @abstractmethod
    def _convert(self, observable: ObservableLike, data: Any) -> None:
        """Convert fetched data to STIX objects."""
