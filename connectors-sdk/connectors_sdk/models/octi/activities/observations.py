"""Offer observations OpenCTI entities."""

import ipaddress
from typing import Any

from connectors_sdk.models._model_registry import MODEL_REGISTRY
from connectors_sdk.models._observable import Observable
from connectors_sdk.models.octi.enums import HashAlgorithm
from pydantic import AwareDatetime, Field, PositiveInt, field_validator, model_validator
from stix2.v21 import URL as Stix2URL  # noqa: N811 # URL is not a constant but a class
from stix2.v21 import DomainName as Stix2DomainName
from stix2.v21 import File as Stix2File
from stix2.v21 import IPv4Address as Stix2IPv4Address
from stix2.v21 import IPv6Address as Stix2IPv6Address
from stix2.v21 import Software as Stix2Software


@MODEL_REGISTRY.register
class DomainName(Observable):
    """Define a domain name observable on OpenCTI.

    Notes:
        - The `resolves_to_refs` (from STIX2.1 spec) field is not implemented on OpenCTI.
          It must be replaced by explicit `resolves-to` relationships.

    """

    value: str = Field(
        description="Specifies the value of the domain name.",
        min_length=1,
    )

    def to_stix2_object(self) -> Stix2DomainName:
        """Make stix object."""
        return Stix2DomainName(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            allow_custom=True,
            **self._custom_properties_to_stix(),
        )


@MODEL_REGISTRY.register
class File(Observable):
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
            object_marking_refs=[marking.id for marking in self.markings or []],
            allow_custom=True,
            x_opencti_additional_names=self.additional_names,
            **self._custom_properties_to_stix(),
        )


@MODEL_REGISTRY.register
class IPV4Address(Observable):
    """Define an IP V4 address observable on OpenCTI.

    Examples:
        >>> ip = IPV4Address(
        ...     value="127.0.0.1/24",
        ...     create_indicator=True,
        ...     )
        >>> entity = ip.to_stix2_object()

    Notes:
        - The `resolves_to_refs` (from STIX2.1 spec) field is not implemented on OpenCTI.
          It must be replaced by explicit `resolves-to` relationships.
        - The `belongs_to_refs` (from STIX2.1 spec) field is not implemented on OpenCTI.
          It must be replaced by explicit `belongs-to` relationships.
    """

    value: str = Field(
        description="The IP address value. CIDR is allowed.",
        min_length=1,
    )

    @field_validator("value", mode="before")
    @classmethod
    def _validate_value(cls, value: str) -> str:
        """Validate the value of the IP V4 address."""
        try:
            ipaddress.ip_network(
                value, strict=False
            )  # strict=False allows CIDR notation
        except ValueError:
            raise ValueError(f"Invalid IP V4 address {value}") from None
        return value

    def to_stix2_object(self) -> Stix2IPv4Address:
        """Make stix object."""
        return Stix2IPv4Address(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            allow_custom=True,
            **self._custom_properties_to_stix(),
        )


@MODEL_REGISTRY.register
class IPV6Address(Observable):
    """Define an IP V6 address observable on OpenCTI.

    Examples:
        >>> ip = IPV6Address(
        ...     value="b357:5b10:0f48:d182:0140:494c:8fe9:6eda",
        ...     create_indicator=True,
        ...     )
        >>> entity = ip.to_stix2_object()

    Notes:
        - The `resolves_to_refs` (from STIX2.1 spec) field is not implemented on OpenCTI.
          It must be replaced by explicit `resolves-to` relationships.
        - The `belongs_to_refs` (from STIX2.1 spec) field is not implemented on OpenCTI.
          It must be replaced by explicit `belongs-to` relationships.
    """

    value: str = Field(
        description="The IP address value. CIDR is allowed.",
        min_length=1,
    )

    @field_validator("value", mode="before")
    @classmethod
    def _validate_value(cls, value: str) -> str:
        """Validate the value of the IP V6 address."""
        try:
            ipaddress.ip_network(
                value, strict=False
            )  # strict=False allows CIDR notation
        except ValueError:
            raise ValueError(f"Invalid IP V6 address {value}") from None
        return value

    def to_stix2_object(self) -> Stix2IPv6Address:
        """Make stix object."""
        return Stix2IPv6Address(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            allow_custom=True,
            **self._custom_properties_to_stix(),
        )


@MODEL_REGISTRY.register
class Software(Observable):
    """Represents a software observable."""

    name: str = Field(
        description="Name of the software.",
        min_length=1,
    )
    version: str | None = Field(
        default=None,
        description="Version of the software.",
    )
    vendor: str | None = Field(
        default=None,
        description="Vendor of the software.",
    )
    swid: str | None = Field(
        default=None,
        description="SWID of the software.",
    )
    cpe: str | None = Field(
        default=None,
        description="CPE of the software.",
    )
    languages: list[str] | None = Field(
        default=None,
        description="Languages of the software.",
    )

    def to_stix2_object(self) -> Stix2Software:
        """Make Software STIX2.1 object."""
        return Stix2Software(
            name=self.name,
            version=self.version,
            vendor=self.vendor,
            swid=self.swid,
            cpe=self.cpe,
            languages=self.languages,
            object_marking_refs=[marking.id for marking in self.markings or []],
            allow_custom=True,
            **self._custom_properties_to_stix(),
        )


@MODEL_REGISTRY.register
class URL(Observable):
    """Represent a URL observable."""

    value: str = Field(
        description="The URL value.",
        min_length=1,
    )

    def to_stix2_object(self) -> Stix2URL:
        """Make stix object."""
        return Stix2URL(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            allow_custom=True,
            **self._custom_properties_to_stix(),
        )


MODEL_REGISTRY.rebuild_all()

if __name__ == "__main__":  # pragma: no cover  # Do not run coverage on doctest
    # import doctest

    # doctest.testmod()

    _ = File(mime_type="text/plain")
