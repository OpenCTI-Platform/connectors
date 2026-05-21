"""BaseAuthorEntity."""

from abc import ABC, abstractmethod

import stix2.properties
from connectors_sdk.models.base_identified_object import BaseIdentifiedObject


class BaseAuthorEntity(BaseIdentifiedObject, ABC):
    """Represent an author.

    BaseAuthorEntity is an OpenCTI concept, a stix-like identity considered as the creator of a
    report or an entity.

    Warning:
        This class cannot be used directly, it must be subclassed.

    """

    @abstractmethod
    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object.

        Returns:
            (stix2.v21._STIXBase21): A stix object representing the author.

        """
