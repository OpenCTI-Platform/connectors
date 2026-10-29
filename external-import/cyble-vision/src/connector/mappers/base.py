"""Base class every per-service mapper implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from connector.mappers.common import AlertContext
from connectors_sdk.models import BaseIdentifiedEntity


class ServiceMapper(ABC):
    """Maps one or more Vision services to STIX objects."""

    services: tuple[str, ...] = ()

    @abstractmethod
    def map(
        self, payload: dict[str, Any], context: AlertContext
    ) -> list[BaseIdentifiedEntity]:
        """Return the STIX objects representing this alert."""
        raise NotImplementedError
