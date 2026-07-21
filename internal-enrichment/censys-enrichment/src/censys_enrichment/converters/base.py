from abc import ABC, abstractmethod
from typing import Any, Mapping

from censys_enrichment.builder import CensysStixBuilder
from censys_enrichment.client import Client
from connectors_sdk.models import BaseObject

# ``observable`` arrives at the converters in two shapes: a plain
# ``dict`` from the OpenCTI enrichment payload (see
# ``Connector._process``) AND a ``stix2`` object (e.g.
# ``stix2.IPv4Address``) when ``DomainConverter._append_hosts``
# composes ``HostConverter._convert(observable=ip_stix.to_stix2_object(), ...)``
# or when a test passes a ``stix2`` instance directly. Both shapes
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

    def to_stix(
        self, observable: ObservableLike, data: Any | None = None
    ) -> list[BaseObject]:
        """Return the STIX bundle for *observable*.

        If *data* is provided, skip the API fetch and convert it directly —
        useful for tests and for callers that already have the payload.
        """
        self.builder.reset()
        if data is None:
            data = self._fetch_data(observable=observable)
        self._convert(observable=observable, data=data)
        return self.builder.bundle

    def _require_client(self) -> Client:
        if self.client is None:
            raise ValueError("Client is required")
        return self.client

    @abstractmethod
    def _fetch_data(self, observable: ObservableLike) -> Any:
        """Fetch data required for STIX conversion."""

    @abstractmethod
    def _convert(self, observable: ObservableLike, data: Any) -> None:
        """Convert fetched data to STIX objects."""
