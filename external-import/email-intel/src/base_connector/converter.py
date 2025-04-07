import abc
from typing import Any, Generic, TypeVar

from base_connector.config import BaseConnectorConfig
from pycti import OpenCTIConnectorHelper
from pydantic import BaseModel

EntityType = TypeVar("EntityType", bound=BaseModel)
StixType = TypeVar("StixType", bound=dict[str, Any])


class BaseConverter(abc.ABC, Generic[EntityType, StixType]):
    """
    Base class for all converters.

    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: BaseConnectorConfig,
    ) -> None:
        self.helper = helper
        self.config = config

    @abc.abstractmethod
    def to_stix(self, entity: EntityType) -> list[StixType]:
        """Convert the data into STIX 2.1 objects."""
