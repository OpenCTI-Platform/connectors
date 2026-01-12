"""Generic converter for any data to STIX format with configurable mappers.

This module provides a flexible converter that can work with any input data format,
handle both model-based and raw data, and provide consistent error handling through
configurable mapper classes.
"""

import logging
from typing import Any

from connector.src.utils.converters.generic_converter_config import (
    GenericConverterConfig,
)

LOG_PREFIX = "[GenericConverter]"


class GenericConverter:
    """Generic converter for any data to STIX format with flexible mapper handling."""

    def __init__(
        self,
        config: GenericConverterConfig,
        logger: logging.Logger | None = None,
    ):
        """Initialize the generic converter.

        Args:
            config: Configuration specifying mapper, models, exceptions, etc.
            logger: Logger for logging messages

        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)

        self.converted_objects: list[Any] = []
        self.object_id_map: dict[str, str] = {}

    def convert_single(self, input_data: Any, **mapper_kwargs: Any) -> Any | None:
        """Convert a single entity to STIX format.

        Args:
            input_data: The input data to convert
            **mapper_kwargs: Additional parameters to pass to mapper

        Returns:
            STIX object(s) or None if conversion fails

        Raises:
            Configured exception class: If there's an error converting the entity

        """
        entity_id = self.config.get_entity_id(input_data)
        entity_name = self.config.get_entity_name(input_data)

        self._log_conversion_start(
            self.config.display_name_singular or "entity", entity_id, entity_name
        )

        try:
            self.config.validate_input_data(input_data)

            processed_input = self._preprocess_input(input_data)

            mapper = self.config.create_mapper(processed_input, **mapper_kwargs)
            stix_model = mapper.to_stix()

            self.config.validate_output_data(stix_model)

            if self.config.to_stix:
                if hasattr(stix_model, "to_stix2_object"):
                    final_output = stix_model.to_stix2_object()
                else:
                    final_output = stix_model

                final_output = self._postprocess_output(final_output)
            else:
                final_output = stix_model
                final_output = self._postprocess_output(final_output)

            self._track_conversion(entity_id, final_output)

            self.logger.debug(
                "Successfully converted to STIX format",
                {
                    "prefix": LOG_PREFIX,
                    "entity_type": self.config.entity_type,
                    "entity_id": entity_id,
                },
            )
            return final_output

        except Exception as e:
            self._handle_conversion_error(e, entity_id, entity_name)
            return None

    def convert_multiple(
        self, input_data_list: list[Any], **mapper_kwargs: Any
    ) -> list[Any]:
        """Convert multiple entities to STIX format.

        Args:
            input_data_list: list of input data to convert
            **mapper_kwargs: Additional parameters to pass to mappers

        Returns:
            list of STIX objects (successful conversions only)

        """
        converted_objects: list[Any] = []

        self._log_conversion_start(self.config.display_name, count=len(input_data_list))

        self.logger.debug(
            "Starting conversion of entities",
            {
                "prefix": LOG_PREFIX,
                "count": len(input_data_list),
                "entity_type": self.config.entity_type,
            },
        )

        for idx, input_data in enumerate(input_data_list):
            entity_id = self.config.get_entity_id(input_data)
            try:
                result = self.convert_single(input_data, **mapper_kwargs)

                if result is not None:
                    if isinstance(result, list):
                        converted_objects.extend(result)
                        self.logger.debug(
                            "Successfully converted entity (produced multiple objects)",
                            {
                                "prefix": LOG_PREFIX,
                                "entity_type": self.config.entity_type,
                                "index": idx + 1,
                                "total": len(input_data_list),
                                "entity_id": entity_id,
                                "objects_produced": len(result),
                            },
                        )
                    else:
                        converted_objects.append(result)
                        self.logger.debug(
                            "Successfully converted entity",
                            {
                                "prefix": LOG_PREFIX,
                                "entity_type": self.config.entity_type,
                                "index": idx + 1,
                                "total": len(input_data_list),
                                "entity_id": entity_id,
                            },
                        )
                else:
                    self.logger.debug(
                        "No output produced for entity",
                        {
                            "prefix": LOG_PREFIX,
                            "display_name": self.config.display_name_singular,
                            "entity_id": entity_id,
                        },
                    )
            except Exception as e:
                self.logger.warning(
                    "Failed to convert entity",
                    {
                        "prefix": LOG_PREFIX,
                        "display_name": self.config.display_name_singular,
                        "entity_id": entity_id,
                        "error": str(e),
                    },
                )
                continue

        self._log_conversion_result(self.config.display_name, len(converted_objects))
        return converted_objects

    def convert_batch(
        self, input_batches: dict[str, list[Any]], **mapper_kwargs: Any
    ) -> dict[str, list[Any]]:
        """Convert batches of different entity types to STIX format.

        Args:
            input_batches: dictionary mapping entity type names to lists of input data
            **mapper_kwargs: Additional parameters to pass to mappers

        Returns:
            dictionary mapping entity type names to lists of converted STIX objects

        """
        converted_batches = {}

        for entity_type, input_list in input_batches.items():
            if input_list:
                self.logger.info(
                    "Converting batch",
                    {
                        "prefix": LOG_PREFIX,
                        "count": len(input_list),
                        "entity_type": entity_type,
                    },
                )
                converted_batches[entity_type] = self.convert_multiple(
                    input_list, **mapper_kwargs
                )
            else:
                self.logger.debug(
                    "Skipping empty batch",
                    {"prefix": LOG_PREFIX, "entity_type": entity_type},
                )
                converted_batches[entity_type] = []

        return converted_batches

    def get_converted_objects(self) -> list[Any]:
        """Get all converted STIX objects.

        Returns:
            list of all converted STIX objects

        """
        return self.converted_objects.copy()

    def get_object_id_map(self) -> dict[str, str]:
        """Get mapping of original entity IDs to STIX object IDs.

        Returns:
            dictionary mapping original IDs to STIX IDs

        """
        return self.object_id_map.copy()

    def clear_converted_objects(self) -> None:
        """Clear the converted objects cache."""
        self.converted_objects.clear()
        self.object_id_map.clear()

    def convert(self, input_data: Any, **kwargs: Any) -> Any:
        """Convert input data to output format based on to_stix flag.

        This method provides backwards compatibility with the previous interface
        and is a convenience wrapper around convert_single.

        Args:
            input_data: The input data to convert
            **kwargs: Additional parameters to pass to mapper constructor

        Returns:
            STIX objects if to_stix=True, otherwise model objects (but to_stix() is still called for validation)

        Raises:
            Exception: If conversion or validation fails

        """
        return self.convert_single(input_data, **kwargs)

    def _preprocess_input(self, input_data: Any) -> Any:
        """Preprocess input data if preprocessing function is configured.

        Args:
            input_data: The input data to preprocess

        Returns:
            Preprocessed input data

        """
        if self.config.preprocessing_function:
            try:
                return self.config.preprocessing_function(input_data)
            except Exception as e:
                entity_id = self.config.get_entity_id(input_data)
                self.logger.warning(
                    "Preprocessing failed",
                    {
                        "prefix": LOG_PREFIX,
                        "entity_id": entity_id,
                        "error": str(e),
                    },
                )
                return input_data
        return input_data

    def _postprocess_output(self, output_data: Any) -> Any:
        """Postprocess output data if postprocessing function is configured.

        Args:
            output_data: The output data to postprocess

        Returns:
            Postprocessed output data

        """
        if self.config.postprocessing_function:
            try:
                return self.config.postprocessing_function(output_data)
            except Exception as e:
                self.logger.warning(
                    "Postprocessing failed",
                    {"prefix": LOG_PREFIX, "error": str(e)},
                )
                return output_data
        return output_data

    def _track_conversion(self, entity_id: str, stix_output: Any) -> None:
        """Track the conversion in internal caches.

        Args:
            entity_id: Original entity ID
            stix_output: Converted STIX output

        """
        if isinstance(stix_output, list):
            self.converted_objects.extend(stix_output)
            if stix_output and hasattr(stix_output[0], "id"):
                self.object_id_map[entity_id] = stix_output[0].id
        else:
            self.converted_objects.append(stix_output)
            if hasattr(stix_output, "id"):
                self.object_id_map[entity_id] = stix_output.id

    def _handle_conversion_error(
        self, error: Exception, entity_id: str, entity_name: str | None
    ) -> None:
        """Handle conversion errors with proper exception wrapping.

        Args:
            error: The original error
            entity_id: Entity ID for context
            entity_name: Entity name for context | None

        Raises:
            Configured exception class: Wrapped error with additional context

        """
        if entity_name:
            error_msg = f"Error converting {self.config.display_name_singular} '{entity_name}' ({entity_id}): {str(error)}"
        else:
            error_msg = f"Error converting {self.config.display_name_singular} {entity_id}: {str(error)}"

        self.logger.error(
            "Conversion failed",
            {
                "prefix": LOG_PREFIX,
                "entity_type": self.config.entity_type,
                "entity_id": entity_id,
                "error": str(error),
            },
        )

        exception = self.config.create_exception(error_msg, entity_id, entity_name)
        raise exception from error

    def _log_conversion_start(
        self,
        entity_type: str,
        entity_id: str | None = None,
        entity_name: str | None = None,
        count: int | None = None,
    ) -> None:
        """Log the start of a conversion operation.

        Args:
            entity_type: Type of entity being converted
            entity_id: ID of the specific entity (optional)
            entity_name: Name of the specific entity (optional)
            count: Number of entities being converted (optional)

        """
        if entity_id and entity_name:
            self.logger.debug(
                "Converting entity to STIX format",
                {
                    "prefix": LOG_PREFIX,
                    "entity_type": entity_type,
                    "entity_name": entity_name,
                    "entity_id": entity_id,
                },
            )
        elif entity_id:
            self.logger.debug(
                "Converting entity to STIX format",
                {
                    "prefix": LOG_PREFIX,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                },
            )
        elif count:
            self.logger.debug(
                "Converting entities to STIX format",
                {
                    "prefix": LOG_PREFIX,
                    "count": count,
                    "entity_type": entity_type,
                },
            )
        else:
            self.logger.debug(
                "Converting entities to STIX format",
                {"prefix": LOG_PREFIX, "entity_type": entity_type},
            )

    def _log_conversion_result(
        self, entity_type: str, result_count: int | None = None
    ) -> None:
        """Log the result of a conversion operation.

        Args:
            entity_type: Type of entity that was converted
            result_count: Number of entities converted

        """
        if result_count is not None and result_count > 0:
            self.logger.info(
                "Converted entities to STIX format",
                {
                    "prefix": LOG_PREFIX,
                    "count": result_count,
                    "entity_type": entity_type,
                },
            )
        else:
            self.logger.debug(
                "No entities converted to STIX format",
                {"prefix": LOG_PREFIX, "entity_type": entity_type},
            )
