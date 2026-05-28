"""File."""

from typing import Any

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.enums import HashAlgorithm
from pydantic import AwareDatetime, Field, PositiveInt, model_validator
from stix2.v21 import File as Stix2File


class File(BaseObservableEntity):
    """Define a file observable on OpenCTI.

    Notes:
        - The `content_ref` field (from STIX2.1 spec) it not implemented on OpenCTI.
          It must be replaced by explicit `____________________` relationships.
        - The `parent_directory_ref` field (from STIX2.1 spec) is not implemented on OpenCTI.
          It must be replaced by explicit `____________________` relationships.
        - The `contains_refs` field (from STIX2.1 spec) is not implemented on OpenCTI.
          It must be replaced by explicit `____________________` relationships.
    """

    hashes: dict[HashAlgorithm, str] | None = Field(
        default=None,
        description="A dictionary of hashes for the file.",
        min_length=1,
    )
    size: PositiveInt | None = Field(
        default=None,
        description="The size of the file in bytes.",
    )
    name: str | None = Field(
        default=None,
        description="The name of the file.",
    )
    name_enc: str | None = Field(
        default=None,
        description="The observed encoding for the name of the file.",
    )
    magic_number_hex: str | None = Field(
        default=None,
        description="The hexadecimal constant ('magic number') associated with the file format.",
    )
    mime_type: str | None = Field(
        default=None,
        description="The MIME type name specified for the file, e.g., application/msword.",
    )
    ctime: AwareDatetime | None = Field(
        default=None,
        description="Date/time the directory was created.",
    )
    mtime: AwareDatetime | None = Field(
        default=None,
        description="Date/time the directory was last writtend to or modified.",
    )
    atime: AwareDatetime | None = Field(
        default=None,
        description="Date/time the directory was last accessed.",
    )
    additional_names: list[str] | None = Field(
        default=None,
        description="Additional names of the file.",
    )

    @model_validator(mode="before")
    @classmethod
    def _validate_data(cls, data: Any) -> Any:
        """Pre validate data to avoid raising a `stix2.exceptions.AtLeastOnePropertyError` during `self.id` eval.

        Notes:
            The code to create a `File` instance is executed in this order:
                1. Call "before" validators, here `File._validate_data`
                2. Call `self.__init__()`
                    2.1. During init, evaluate `self.id` (computed field from `BaseIdentifiedEntity` superclass)
                        2.1.1. During `self.id` eval, call `self.to_stix2_object()`
                3. Call `self._check_id()` "after" validator (from `BaseIdentifiedEntity` superclass)

            This validator aims to replace the `stix2.exceptions.AtLeastOnePropertyError` that could be raised in
            `self.to_stix2_object()` by a `pydantic.ValidationError`.
        """
        if isinstance(data, dict):
            if not data.get("name") and not data.get("hashes"):
                raise ValueError("Either 'name' or one of 'hashes' must be provided.")

        return data

    def to_stix2_object(self) -> Stix2File:
        """Make stix object."""
        return Stix2File(
            hashes=self.hashes,
            size=self.size,
            name=self.name,
            name_enc=self.name_enc,
            magic_number_hex=self.magic_number_hex,
            mime_type=self.mime_type,
            ctime=self.ctime,
            mtime=self.mtime,
            atime=self.atime,
            x_opencti_additional_names=self.additional_names,
            **self._common_stix2_properties()
        )
