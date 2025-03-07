"""Offer common tools to create octi entities."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Annotated, Any, Callable, Optional

import dragos.domain.models.octi.enum as OCTIEnum
import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
import stix2.exceptions
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, PrivateAttr


def is_in_enum(enum: Enum) -> Callable:
    """Get validator to check if a value is in given enum."""

    def compare_value(value: Any) -> Any:
        """Check if value is in enum."""
        enum_values = [member.value for member in enum]
        if value not in enum_values:
            raise ValueError(
                f"Invalid value '{value}'. Allowed values are: {', '.join(enum_values)}"
            )
        return value

    return compare_value


# Convert Enums to Types in order to manipulate strings (not Enums) in Pydantic models
AccountType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.AccountType))]
EncryptionAlgorithm = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.EncryptionAlgorithm))
]
HashAlgorithm = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.HashAlgorithm))]
IndicatorType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.IndicatorType))]
ObservableType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.ObservableType))]
OrganizationType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.OrganizationType))]
PatternType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.PatternType))]
Platform = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.Platform))]
Reliability = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.Reliability))]
ReportType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.ReportType))]
TLPLevel = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.TLPLevel))]
WindowsRegistryDatatype = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.WindowsRegistryDatatype))
]
WindowsIntegrityLevel = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.WindowsIntegrityLevel))
]
WindowsServiceStartType = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.WindowsServiceStartType))
]
WindowsServiceStatus = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.WindowsServiceStatus))
]
WindowsServiceType = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.WindowsServiceType))
]


class BaseModelWithoutExtra(BaseModel):
    """Represent a Pydantic BaseModel where non explicitly define fields are forbidden."""

    model_config = ConfigDict(
        extra="forbid",
    )

    def __hash__(self) -> int:
        """Create a hash based on the model's json representation dynamically."""
        return hash(self.model_dump_json())

    def __eq__(self, other: Any) -> bool:
        """Implement comparison between similar object."""
        if not isinstance(other, self.__class__):
            raise NotImplementedError("Cannot compare objects from different type.")
        # Compare the attributes by converting them to a dictionary
        return self.model_dump_json() == other.model_dump_json()


class BaseEntity(BaseModelWithoutExtra):
    """Base class to implement common attributes and methods for all entities."""

    model_config = ConfigDict(
        **BaseModelWithoutExtra.model_config,
        arbitrary_types_allowed=True,
    )

    _stix2_representation: Optional[Any] = PrivateAttr(None)
    _id: str = PrivateAttr("")

    def model_post_init(
        self, context__: Any
    ) -> None:  # pylint: disable=unused-argument
        """Define the post initialization method, automatically called after __init__ in a pydantic model initialization.

        Notes:
            This allows a last modification of the pydantic Model before it is eventually frozen.

        Args:
            context__(Any): The pydantic context used by pydantic framework.

        References:
            https://docs.pydantic.dev/latest/api/base_model/#pydantic.BaseModel.model_parametrized_name [consulted on
                October 4th, 2024]

        """
        try:
            self._stix2_representation = self.to_stix2_object()
        except stix2.exceptions.STIXError as err:
            # Wrap STIXError so Pydantic can catch it and raise its own ValidationError
            raise ValueError(str(err)) from err

        self._id = self._stix2_representation["id"]

    @abstractmethod
    def to_stix2_object(self) -> stix2.v21._STIXBase21:  # noqa: W0212
        """Make stix object (usually from stix2 python lib objects)."""

    @property
    def id(self) -> str:
        """Return the unique identifier of the entity."""
        return self._id


class ExternalReference(BaseModelWithoutExtra):
    """Represents an external reference to a source of information."""

    source_name: str = Field(
        ...,
        description="The name of the source of the external reference.",
    )
    description: Optional[str] = Field(
        None,
        description="Description of the external reference.",
    )
    url: Optional[str] = Field(
        None,
        description="URL of the external reference.",
    )
    external_id: Optional[str] = Field(
        None,
        description="An identifier for the external reference content.",
    )

    def to_stix2_object(self) -> stix2.v21.ExternalReference:
        """Make stix object."""
        return stix2.ExternalReference(
            source_name=self.source_name,
            description=self.description,
            url=self.url,
            external_id=self.external_id,
            # unused
            hashes=None,
        )


class KillChainPhase(BaseModelWithoutExtra):
    """Represent a kill chain phase."""

    chain_name: str = Field(..., description="Name of the kill chain.")
    phase_name: str = Field(..., description="Name of the kill chain phase.")

    def to_stix2_object(self) -> stix2.v21.KillChainPhase:
        """Make stix object."""
        return stix2.KillChainPhase(
            kill_chain_name=self.chain_name,
            phase_name=self.phase_name,
        )


class Author(ABC, BaseEntity):
    """Represent an author.

    Warning:
        This class cannot be used directly, it must be subclassed.

    """

    @abstractmethod
    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object."""
        raise NotImplementedError()


class TLPMarking(BaseEntity):
    """Represent a TLP marking definition."""

    level: TLPLevel = Field(
        ...,
        description="The level of the marking.",
    )

    def to_stix2_object(self) -> stix2.v21.MarkingDefinition:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        mapping = {
            "white": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties=dict(  # noqa: C408  # No literal dict for maintainability
                    x_opencti_definition_type="TLP",
                    x_opencti_definition="TLP:AMBER+STRICT",
                ),
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[self.level]
