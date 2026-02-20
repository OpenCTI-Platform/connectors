"""Define the OpenCTI Observables."""

import ipaddress
from abc import abstractmethod
from typing import Any, Optional, Self

import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
from dragos.domain.models.octi.common import (
    Author,
    BaseEntity,
    ExternalReference,
    TLPMarking,
)
from dragos.domain.models.octi.domain import Indicator
from dragos.domain.models.octi.enums import (
    HashAlgorithm,
    ObservableType,
    PatternType,
)
from pydantic import AwareDatetime, Field, PositiveInt, field_validator, model_validator


class Observable(BaseEntity):
    """Base class for OpenCTI Observables.

    NOTA BENE: Observables do not need deterministic stix id generation. STIX python lib handles it.
    """

    score: Optional[int] = Field(
        None,
        description="Score of the observable.",
        ge=0,
        le=100,
    )
    description: Optional[str] = Field(
        None,
        description="Description of the observable.",
    )
    labels: Optional[list[str]] = Field(
        None,
        description="Labels of the observable.",
    )
    external_references: Optional[list[ExternalReference]] = Field(
        None,
        description="External references of the observable.",
    )
    markings: Optional[list[TLPMarking]] = Field(
        None,
        description="References for object marking.",
    )
    author: Optional[Author] = Field(
        None,
        description="The Author reporting this Observable.",
    )

    def _custom_properties_to_stix(self) -> dict[str, Any]:
        """Factorize custom params."""
        return dict(  # noqa: C408 # No literal dict for maintainability
            x_opencti_score=self.score,
            x_opencti_description=self.description,
            x_opencti_labels=self.labels,
            x_opencti_external_references=[
                external_ref.to_stix2_object()
                for external_ref in self.external_references or []
            ],
            x_opencti_created_by_ref=self.author.id if self.author else None,
        )

    @abstractmethod
    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object."""

    @abstractmethod
    def to_indicator(
        self,
        valid_from: Optional[AwareDatetime] = None,
        valid_until: Optional[AwareDatetime] = None,
    ) -> Indicator:
        """Make stix indicator based on current observable."""


class DomainName(Observable):
    """Represent a domain name observable on OpenCTI."""

    value: str = Field(
        ...,
        description="Specifies the value of the domain name.",
        min_length=1,
    )

    def to_stix2_object(self) -> stix2.DomainName:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        return stix2.DomainName(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties=self._custom_properties_to_stix(),
            # unused
            resolves_to_refs=None,  # not implemented on OpenCTI
            granular_markings=None,
            defanged=None,
            extensions=None,
        )

    def to_indicator(
        self,
        valid_from: Optional[AwareDatetime] = None,
        valid_until: Optional[AwareDatetime] = None,
    ) -> Indicator:
        """Make stix indicator based on current observable.

        - Indicator's name is the value of the domain name.
        - Indicator's pattern is the value of the domain name.
        """
        return Indicator(
            name=self.value,
            pattern=f"[domain-name:value='{self.value}']",
            pattern_type=PatternType.STIX.value,
            observable_type=ObservableType.DOMAIN_NAME.value,
            description=self.description,
            valid_from=valid_from,
            valid_until=valid_until,
            score=self.score,
            author=self.author,
            markings=self.markings,
            external_references=self.external_references,
        )


class File(Observable):
    """Represent a file observable on OpenCTI."""

    hashes: Optional[dict[HashAlgorithm, str]] = Field(
        None,
        description="A dictionary of hashes for the file.",
        min_length=1,
    )
    size: Optional[PositiveInt] = Field(
        None,
        description="The size of the file in bytes.",
    )
    name: Optional[str] = Field(
        None,
        description="The name of the file.",
    )
    name_enc: Optional[str] = Field(
        None,
        description="The observed encoding for the name of the file.",
    )
    magic_number_hex: Optional[str] = Field(
        None,
        description="The hexadecimal constant ('magic number') associated with the file format.",
    )
    mime_type: Optional[str] = Field(
        None,
        description="The MIME type name specified for the file, e.g., application/msword.",
    )
    ctime: Optional[AwareDatetime] = Field(
        None,
        description="Date/time the directory was created.",
    )
    mtime: Optional[AwareDatetime] = Field(
        None,
        description="Date/time the directory was last writtend to or modified.",
    )
    atime: Optional[AwareDatetime] = Field(
        None,
        description="Date/time the directory was last accessed.",
    )
    additional_names: Optional[list[str]] = Field(
        None,
        description="Additional names of the file.",
    )

    @model_validator(mode="after")
    def _validate_model(self) -> Self:
        """Add further validation after model initialization. Automatically called by Pydantic."""
        if not self.name and not self.hashes:
            raise ValueError("Either 'name' or one of 'hashes' must be provided.")
        return self

    def _custom_properties_to_stix(self) -> dict[str, Any]:
        """Convert custom properties to stix."""
        custom_properties = super()._custom_properties_to_stix()
        custom_properties.update({"x_opencti_additional_names": self.additional_names})
        return custom_properties

    def to_stix2_object(self) -> stix2.File:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        return stix2.File(
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
            custom_properties=self._custom_properties_to_stix(),
            # unused
            parent_directory_ref=None,  # not implemented on OpenCTI
            contains_refs=None,  # not implemented on OpenCTI
            content_ref=None,  # not implemented on OpenCTI
            granular_markings=None,
            defanged=None,
            extensions=None,
        )

    def to_indicator(
        self,
        valid_from: Optional[AwareDatetime] = None,
        valid_until: Optional[AwareDatetime] = None,
    ) -> Indicator:
        """Make stix indicator based on current observable.

        - Indicator's name is either the name or the first hash value of the file.
        - Indicator's pattern is a combination of the name and the hash values of the file.
        """
        name = self.name or (list(self.hashes.values())[0] if self.hashes else None)

        stix_pattern = None
        comparison_expressions = []
        if self.name:
            comparison_expressions.append(f"file:name='{self.name}'")
        if self.hashes:
            for key in self.hashes:
                comparison_expressions.append(
                    f"file:hashes.'{key}'='{self.hashes[key]}'"
                )
        if comparison_expressions:
            stix_pattern = f"[{' AND '.join(comparison_expressions)}]"

        return Indicator(
            name=name,
            pattern=stix_pattern,
            pattern_type=PatternType.STIX.value,
            observable_type=ObservableType.FILE.value,
            description=self.description,
            valid_from=valid_from,
            valid_until=valid_until,
            score=self.score,
            author=self.author,
            markings=self.markings,
            external_references=self.external_references,
        )


class IPV4Address(Observable):
    """Represent an IP address observable on OpenCTI."""

    value: str = Field(
        ...,
        description="The IP address value.",
        min_length=1,
    )

    @field_validator("value", mode="before")
    @classmethod
    def _validate_value(cls, value: str) -> str:
        """Validate the value of the IP V4 address."""
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            raise ValueError(f"Invalid IP V4 address {value}") from None
        return value

    def to_stix2_object(self) -> stix2.v21.IPv4Address:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        return stix2.IPv4Address(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties=self._custom_properties_to_stix(),
            # unused
            resolves_to_refs=None,  # not implemented on OpenCTI, this has to be an explicit resolves to mac address relationships
            belongs_to_refs=None,  # not implemented on OpenCTI, this has to be an explicit belongs to autonomous system relationship
            granular_markings=None,
            defanged=None,
            extensions=None,
        )

    def to_indicator(
        self,
        valid_from: Optional[AwareDatetime] = None,
        valid_until: Optional[AwareDatetime] = None,
    ) -> Indicator:
        """Make stix indicator based on current observable.

        - Indicator's name is the value of the IP address.
        - Indicator's pattern is the value of the IP address.
        """
        return Indicator(
            name=self.value,
            pattern=f"[ipv4-addr:value='{self.value}']",
            pattern_type=PatternType.STIX.value,
            observable_type=ObservableType.IPV4_ADDR.value,
            description=self.description,
            valid_from=valid_from,
            valid_until=valid_until,
            score=self.score,
            author=self.author,
            markings=self.markings,
            external_references=self.external_references,
        )


class IPV6Address(Observable):
    """Represent an IP address observable on OpenCTI."""

    value: str = Field(
        ...,
        description="The IP address value.",
        min_length=1,
    )

    @field_validator("value", mode="before")
    @classmethod
    def _validate_value(cls, value: str) -> str:
        """Validate the value of the IP V6 address."""
        try:
            ipaddress.IPv6Address(value)
        except ValueError:
            raise ValueError(f"Invalid IP V6 address {value}") from None
        return value

    def to_stix2_object(self) -> stix2.v21.IPv6Address:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        return stix2.IPv6Address(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties=self._custom_properties_to_stix(),
            # unused
            resolves_to_refs=None,  # not implemented on OpenCTI, his has to be an explicit resolves to mac address relationships
            belongs_to_refs=None,  # not implemented on OpenCTI, his has to be an explicit belongs to autonomous system relationship
            granular_markings=None,
            defanged=None,
            extensions=None,
        )

    def to_indicator(
        self,
        valid_from: Optional[AwareDatetime] = None,
        valid_until: Optional[AwareDatetime] = None,
    ) -> Indicator:
        """Make stix indicator based on current observable.

        - Indicator's name is the value of the IP address.
        - Indicator's pattern is the value of the IP address.
        """
        return Indicator(
            name=self.value,
            pattern=f"[ipv6-addr:value='{self.value}']",
            pattern_type=PatternType.STIX.value,
            observable_type=ObservableType.IPV6_ADDR.value,
            description=self.description,
            valid_from=valid_from,
            valid_until=valid_until,
            score=self.score,
            author=self.author,
            markings=self.markings,
            external_references=self.external_references,
        )


class Url(Observable):
    """Represent a URL observable."""

    value: str = Field(
        ...,
        description="The URL value.",
        min_length=1,
    )

    def to_stix2_object(self) -> stix2.v21.URL:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        return stix2.URL(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties=self._custom_properties_to_stix(),
            # unused
            granular_markings=None,
            defanged=None,
            extensions=None,
        )

    def to_indicator(
        self,
        valid_from: Optional[AwareDatetime] = None,
        valid_until: Optional[AwareDatetime] = None,
    ) -> Indicator:
        """Make stix indicator based on current observable.

        - Indicator's name is the value of the url.
        - Indicator's pattern is the value of the url.
        """
        return Indicator(
            name=self.value,
            pattern=f"[url:value='{self.value}']",
            pattern_type=PatternType.STIX.value,
            observable_type=ObservableType.URL.value,
            description=self.description,
            valid_from=valid_from,
            valid_until=valid_until,
            score=self.score,
            author=self.author,
            markings=self.markings,
            external_references=self.external_references,
        )
