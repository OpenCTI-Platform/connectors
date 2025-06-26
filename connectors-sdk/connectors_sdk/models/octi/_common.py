"""Offer common tools to for OpenCTI models."""

import codecs
import warnings
from abc import ABC, abstractmethod
from typing import Any, Literal, Optional, OrderedDict, TypeVar

import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
import stix2.properties  # type: ignore[import-untyped]
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    computed_field,
    model_validator,
)

T = TypeVar("T", bound=BaseModel)  # Preserve metadata when using register decorator


class _ModelRegistry:
    """Singleton registry for OpenCTI models."""

    _instance: Optional["_ModelRegistry"] = None
    _initialized: bool = False

    def __new__(cls) -> "_ModelRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if _ModelRegistry._initialized:
            return
        self.models: dict[str, type[BaseModel]] = {}
        _ModelRegistry._initialized = True

    def register(self, model_class: type[T]) -> type[T]:
        """Register a model class in the registry.

        Args:
            model_class (BaseModel-like): The model class to register.

        Returns:
            BaseModel-like: The registered model class.
        """
        self.models[model_class.__name__] = model_class
        return model_class

    def rebuild_all(self) -> None:
        for model in self.models.values():
            model.model_rebuild(_types_namespace=self.models)


MODEL_REGISTRY = _ModelRegistry()


@MODEL_REGISTRY.register
class BaseEntity(BaseModel):
    """Represent Base Entity for OpenCTI models."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,  # ensure model is revalidate when setting properties
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

    @property
    def properties_set(self) -> set[str]:
        """Return the set of explicitely set fields.
        Set properties must be included in the stix object output.
        """
        return self.model_fields_set

    @property
    def properties_unset(self) -> set[str]:
        """Return the set of unset properties.

        Unset properties must be excluded from the stix object output (no update, but no deletion either, contrary to an explicitely field set to None).
        """
        # lighter to make the diff rather than checking during set comprehension.
        return {str(k) for k in self.__pydantic_fields__.keys()} - self.properties_set

    @abstractmethod
    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object (usually from stix2 python lib objects)."""


@MODEL_REGISTRY.register
class BaseIdentifiedEntity(BaseEntity):
    """Base class that can be identified thanks to a stix-like id."""

    _stix2_id: Optional[str] = PrivateAttr(None)

    author: Optional["Author"] = Field(
        None,
        description="The Author reporting this Observable.",
    )

    markings: Optional[list["TLPMarking"]] = Field(
        None,
        description="References for object marking.",
    )

    external_references: Optional[list["ExternalReference"]] = Field(
        None,
        description="External references of the observable.",
    )

    def model_post_init(self, context__: Any) -> None:
        """Define the post initialization method, automatically called after __init__ in a pydantic model initialization.

        Notes:
            This allows a last modification of the pydantic Model before it is validated.

        Args:
            context__(Any): The pydantic context used by pydantic framework.

        References:
            https://docs.pydantic.dev/latest/api/base_model/#pydantic.BaseModel.model_parametrized_name [consulted on
                October 4th, 2024]

        """
        _ = context__  # Unused parameter, but required by pydantic
        if self._stix2_id is None:
            self._stix2_id = self.id

    @computed_field  # type: ignore[prop-decorator]
    # known issue : see https://docs.pydantic.dev/2.3/usage/computed_fields/ (consulted on 2025-06-06)
    @property
    def id(self) -> str:
        """Return the unique identifier of the entity."""
        stix_id: str = self.to_stix2_object().get("id", "")
        self._stix2_id = stix_id
        return stix_id

    @id.setter
    def id(self, value: str) -> None:
        """Prevent setting the id property."""
        raise AttributeError(
            f"The 'id' property is read-only and cannot be modified with {value}."
        )

    # https://github.com/pydantic/pydantic/discussions/10098
    @model_validator(mode="after")
    def _check_id(self) -> "BaseIdentifiedEntity":
        """Ensure the id is correctly set and alert if it has changed.

        Raises:
            ValueError: If the id is not set.
            UserWarning: If the id has changed since the last time it was set.

        Examples:
            >>> class Toto(BaseIdentifiedEntity):
            ...     # Example class that changes its id when value is changed.
            ...     titi: str
            ...     def to_stix2_object(self):
            ...         return stix2.v21.Identity(
            ...             id=f"identity--011fe1ae-7b92-4779-9eb5-7be2aeffb9e{self.titi}",
            ...             name="Test Identity",
            ...             identity_class="individual",
            ...         )
            >>> toto = Toto(titi="2")
            >>> toto.id
            'identity--011fe1ae-7b92-4779-9eb5-7be2aeffb9e2'
            >>> toto.titi = "1" # This will raise a warning
            >>> toto.id
            'identity--011fe1ae-7b92-4779-9eb5-7be2aeffb9e1'

        """
        if self._stix2_id is None or self._stix2_id == "":
            raise ValueError("The 'id' property must be set.")

        if self._stix2_id != self.id:
            # define message before the warning to avoid self._stix2_id has already changed in the main thread
            message = (
                f"The 'id' property has changed from to {self.id}. "
                "This may lead to unexpected behavior in the OpenCTI platform."
            )
            warnings.warn(
                message=message,
                category=UserWarning,
                stacklevel=2,
            )
        self._stix2_id = self.id  # Update the internal id to the current one
        return self


class AssociatedFileStix(stix2.v21._STIXBase21):  # type: ignore[misc]
    # As stix2 is untyped, subclassing one of its element is not handled by type checkers.
    # Note: This is a candidate for refactoring in the pycti package.
    """Stix like object for Associated File.

    Examples:
        >>> associated_file_stix = AssociatedFileStix(
        ...     name="example_file.txt",
        ...     data="VGhpcyBpcyBhbiBleGFtcGxlIGZpbGUgY29udGVudC4=",  # Base64 encoded content
        ...     mime_type="text/plain",
        ...     object_marking_refs=[stix2.TLP_WHITE.get("id")],
        ...     version="1.0"
        ... )

    """

    _properties = OrderedDict(
        [
            ("spec_version", stix2.properties.StringProperty(fixed="2.1")),
            ("name", stix2.properties.StringProperty()),
            ("data", stix2.properties.StringProperty(default=None)),
            ("mime_type", stix2.properties.StringProperty(default=None)),
            ("description", stix2.properties.StringProperty(default=None)),
            (
                "object_marking_refs",
                stix2.properties.ListProperty(
                    stix2.properties.ReferenceProperty(
                        valid_types="marking-definition", spec_version="2.1"
                    )
                ),
            ),
            ("version", stix2.properties.StringProperty(default=None)),
            ("no_import_flag", stix2.properties.BooleanProperty(default=False)),
        ]
    )


@MODEL_REGISTRY.register
class AssociatedFile(BaseEntity):
    """Represents a SDO's or SCO's corresponding file, such as a Report PDF or an Artifact binary.

    Examples:
        >>> associated_file = AssociatedFile(
        ...     name="example_file.txt",
        ...     description="An example file for demonstration purposes.",
        ...     content=b"qwerty",
        ...     mime_type="text/plain",
        ...     markings=[TLPMarking(level="white")],
        ...     )

    """

    name: str = Field(
        description="The name of the file.",
    )
    description: Optional[str] = Field(
        None,
        description="Description of the file.",
    )
    content: Optional[bytes] = Field(
        None,
        description="The file content.",
    )
    mime_type: Optional[str] = Field(
        None,
        description="File mime type.",
    )
    markings: Optional[list["TLPMarking"]] = Field(
        None,
        description="References for object marking.",
    )
    version: Optional[str] = Field(
        None,
        description="Version of the file.",
    )

    def to_stix2_object(self) -> AssociatedFileStix:
        """Make stix-like object (not defined in stix spec nor lib).

        Returns:
            (AssociatedFileStix): A stix like object, defigning a file to upload into the OCTI platform

        """
        return AssociatedFileStix(
            name=self.name,
            description=self.description,
            data=(
                codecs.encode(self.content, "base64").decode("utf-8")
                if self.content
                else None
            ),
            mime_type=self.mime_type,
            object_marking_refs=(
                [marking.id for marking in self.markings or []]
                if self.markings
                else None
            ),
            version=self.version,
        )


@MODEL_REGISTRY.register
class Author(ABC, BaseIdentifiedEntity):
    """Represent an author.

    Author is an OpenCTI concept, a stix-like identity considered as the creator of a
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


@MODEL_REGISTRY.register
class TLPMarking(BaseIdentifiedEntity):
    """Represent a TLP marking definition."""

    level: Literal["white", "green", "amber", "amber+strict", "red"] = Field(
        description="The level of the TLP marking.",
    )

    def to_stix2_object(self) -> stix2.v21.MarkingDefinition:
        """Make stix object."""
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


@MODEL_REGISTRY.register
class ExternalReference(BaseEntity):
    """Represents an external reference to a source of information."""

    source_name: str = Field(
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


# See https://docs.pydantic.dev/latest/errors/usage_errors/#class-not-fully-defined (consulted on 2025-06-10)
MODEL_REGISTRY.rebuild_all()


if __name__ == "__main__":  # pragma: no cover # Do not compute coverage on doctest
    import doctest

    doctest.testmod()
