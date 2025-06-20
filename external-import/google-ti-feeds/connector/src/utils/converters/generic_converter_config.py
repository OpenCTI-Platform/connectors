"""Generic converter configuration for any data to STIX format conversion.

This module provides a flexible configuration system for creating converters
that can work with any input data format, mapper class, and output STIX entity type.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Type

from pydantic import BaseModel


class BaseMapper(ABC):
    """Abstract base class for all mappers."""

    @abstractmethod
    def to_stix(self) -> Any:
        """Convert input data to STIX format.

        Returns:
            STIX object or list of STIX objects

        """
        pass


@dataclass
class GenericConverterConfig:
    """Configuration for a generic data to STIX converter.

    This configuration allows creating converters for any input data format
    with flexible mapper classes and output STIX entity types.
    """

    entity_type: str
    """The type of entity being converted (e.g., 'malware', 'threat_actors', 'reports')"""

    mapper_class: Type[BaseMapper]
    """The mapper class responsible for the actual conversion"""

    output_stix_type: str
    """The STIX object type being produced (e.g., 'malware', 'intrusion-set', 'report')"""

    exception_class: Type[Exception]
    """Exception class to raise on conversion errors"""

    display_name: str
    """Human-readable name for logging and error messages (e.g., 'malware families', 'threat actors')"""

    input_model: Optional[Type[BaseModel]] = None
    """Optional input model type for validation. If None, accepts raw data"""

    display_name_singular: Optional[str] = None
    """Singular form of display name. Auto-generated if not provided"""

    validate_input: bool = True
    """Whether to validate input data before conversion"""

    validate_output: bool = True
    """Whether to validate STIX output after conversion"""

    additional_dependencies: Optional[Dict[str, Any]] = None
    """Additional dependencies to pass to mapper (e.g., organization, tlp_marking)"""

    id_field: str = "id"
    """Field name that contains the entity ID for tracking and logging"""

    name_field: Optional[str] = None
    """Optional field name that contains the entity name for logging"""

    required_attributes: Optional[List[str]] = None
    """List of required attributes that input data must have"""

    preprocessing_function: Optional[Callable[[Any], Any]] = None
    """Optional function to preprocess input data before conversion"""

    postprocessing_function: Optional[Callable[[Any], Any]] = None
    """Optional function to postprocess STIX output after conversion"""

    to_stix: bool = True
    """Whether to return STIX objects (True) or mapper objects (False). If False, still calls to_stix() for validation"""

    def __post_init__(self) -> None:
        """Post-initialization to set defaults."""
        if self.display_name_singular is None:
            if self.display_name.endswith("s") and len(self.display_name) > 1:
                self.display_name_singular = self.display_name[:-1]
            else:
                self.display_name_singular = self.display_name

        if self.additional_dependencies is None:
            self.additional_dependencies = {}

        if self.required_attributes is None:
            self.required_attributes = []

    def create_mapper(self, input_data: Any, **kwargs: Any) -> Any:
        """Create a mapper instance with the input data and dependencies.

        Args:
            input_data: The input data to convert
            **kwargs: Additional parameters to pass to mapper constructor

        Returns:
            Mapper instance ready for conversion

        Raises:
            TypeError: If mapper cannot be instantiated with provided parameters

        """
        mapper_args = {**(self.additional_dependencies or {}), **kwargs}

        mapper_class: Any = self.mapper_class

        try:
            instance: Any = mapper_class(input_data, **mapper_args)
            return instance
        except TypeError as e:
            try:
                mapper: Any = mapper_class(**mapper_args)
                if hasattr(mapper, "set_input_data"):
                    mapper.set_input_data(input_data)
                return mapper
            except TypeError:
                class_name = str(mapper_class)
                raise TypeError(
                    f"Cannot instantiate mapper {class_name} with provided parameters: {str(e)}"
                ) from e

    def create_exception(
        self,
        message: str,
        entity_id: Optional[str] = None,
        entity_name: Optional[str] = None,
        **kwargs: Any,
    ) -> Exception:
        """Create an exception instance with the configured exception class.

        Args:
            message: Error message
            entity_id: Optional entity ID for context
            entity_name: Optional entity name for context
            **kwargs: Additional parameters to pass to exception constructor

        Returns:
            Exception instance

        """
        try:
            return self.exception_class(message, entity_id, entity_name, **kwargs)
        except TypeError:
            try:
                return self.exception_class(message, entity_id, **kwargs)
            except TypeError:
                try:
                    return self.exception_class(message, **kwargs)
                except TypeError:
                    return self.exception_class(message)

    def get_entity_id(self, input_data: Any) -> str:
        """Extract entity ID from input data.

        Args:
            input_data: The input data

        Returns:
            Entity ID string

        """
        try:
            if hasattr(input_data, self.id_field):
                return str(getattr(input_data, self.id_field))
            elif isinstance(input_data, dict) and self.id_field in input_data:
                return str(input_data[self.id_field])
            else:
                return "unknown"
        except (AttributeError, KeyError, TypeError):
            return "unknown"

    def get_entity_name(self, input_data: Any) -> Optional[str]:
        """Extract entity name from input data if name_field is configured.

        Args:
            input_data: The input data

        Returns:
            Entity name string or None

        """
        if not self.name_field:
            return None

        try:
            if hasattr(input_data, self.name_field):
                return str(getattr(input_data, self.name_field))
            elif isinstance(input_data, dict) and self.name_field in input_data:
                return str(input_data[self.name_field])
            else:
                return None
        except (AttributeError, KeyError, TypeError):
            return None

    def validate_input_data(self, input_data: Any) -> None:
        """Validate input data according to configuration.

        Args:
            input_data: The input data to validate

        Raises:
            ValueError: If input data is invalid

        """
        if not self.validate_input:
            return

        self._validate_against_model(input_data)

        self._validate_required_attributes(input_data)

    def _validate_against_model(self, input_data: Any) -> None:
        """Validate input data against the configured input model.

        Args:
            input_data: The input data to validate

        Raises:
            ValueError: If input data doesn't match the model

        """
        if not self.input_model:
            return

        if not isinstance(input_data, BaseModel):
            if hasattr(self.input_model, "model_validate"):
                try:
                    self.input_model.model_validate(input_data)
                except Exception as e:
                    raise ValueError(f"Input data validation failed: {str(e)}") from e
            else:
                model_name = getattr(
                    self.input_model, "__name__", str(self.input_model)
                )
                raise ValueError(f"Input data must be of type {model_name}")

    def _validate_required_attributes(self, input_data: Any) -> None:
        """Check that input data has all required attributes.

        Args:
            input_data: The input data to validate

        Raises:
            ValueError: If a required attribute is missing

        """
        for attr in self.required_attributes or []:
            if hasattr(input_data, attr):
                if not getattr(input_data, attr):
                    raise ValueError(f"Required attribute '{attr}' is missing or empty")
            elif isinstance(input_data, dict):
                if attr not in input_data or not input_data[attr]:
                    raise ValueError(f"Required attribute '{attr}' is missing or empty")
            else:
                raise ValueError(f"Required attribute '{attr}' not found in input data")

    def validate_output_data(self, output_data: Any) -> None:
        """Validate output STIX data.

        Args:
            output_data: The output STIX data to validate

        Raises:
            ValueError: If output data is invalid

        """
        if not self.validate_output:
            return

        if output_data is None:
            raise ValueError("Conversion produced no output")

        if hasattr(output_data, "type"):
            if not hasattr(output_data, "id"):
                raise ValueError("STIX object missing required 'id' field")
        elif isinstance(output_data, list):
            for i, obj in enumerate(output_data):
                if not hasattr(obj, "type"):
                    raise ValueError(
                        f"Object at index {i} is not a valid STIX object (missing 'type')"
                    )
                if not hasattr(obj, "id"):
                    raise ValueError(
                        f"Object at index {i} is missing required 'id' field"
                    )
        else:
            raise ValueError("Output must be a STIX object or list of STIX objects")
