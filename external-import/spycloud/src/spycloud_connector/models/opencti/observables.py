from abc import abstractmethod
from typing import Optional

import pycti
import stix2
from pydantic import Field

from spycloud_connector.models.opencti import OCTIBaseModel, Author, TLPMarking


class ObservableBaseModel(OCTIBaseModel):
    """
    Represents observables associated with a system or an asset.
    NOTA BENE: Observables do not need determinitic stix id generation. STIX python lib handles it.
    """

    markings: Optional[list[TLPMarking]] = Field(
        description="References for object marking.",
        default=[],
    )
    author: Author = Field(description="The Author reporting this observable.")

    @abstractmethod
    def to_stix2_object(self) -> stix2.v21._Observable:
        """Make stix object."""


class DomainName(ObservableBaseModel):
    """Represent a domain name observable in OpenCTI."""

    value: str = Field(
        description="Specifies the value of the domain name.",
        min_length=1,
    )

    def to_stix2_object(self) -> stix2.DomainName:
        return stix2.DomainName(
            value=self.value,
            object_marking_refs=self.markings,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class EmailAddress(ObservableBaseModel):
    """Represent an email address observable in OpenCTI."""

    value: str = Field(
        description="Specifies the value of the email address. This MUST NOT include the display name.",
        min_length=1,
    )
    display_name: Optional[str] = Field(
        description="Specifies a single email display name, i.e., the name that is displayed to the human user of a mail application.",
        min_length=1,
        default=None,
    )
    belongs_to_ref: Optional[str] = Field(
        description="Specifies the user account that the email address belongs to, as a reference to a User Account object.",
        default=None,
    )

    def to_stix2_object(self) -> stix2.EmailAddress:
        return stix2.EmailAddress(
            value=self.value,
            display_name=self.display_name,
            belongs_to_ref=self.belongs_to_ref,
            object_marking_refs=self.markings,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class File(ObservableBaseModel):
    """Represent a file observable in OpenCTI."""

    name: Optional[str] = Field(
        description="Specifies the name of the file.",
        min_length=1,
        default=None,
    )
    hashes: Optional[dict] = Field(
        description="Specifies a dictionary of hashes for the file.",
        default=None,
    )

    def to_stix2_object(self) -> stix2.File:
        return stix2.File(
            name=self.name,
            hashes=self.hashes,
            object_marking_refs=self.markings,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class IPV4Address(ObservableBaseModel):
    """Represent an IP address observable."""

    value: str = Field(
        description="Specifies the value of one IPv4 address.",
        min_length=1,
    )

    # @field_validator("value", mode="before")
    # @classmethod
    # def validate_value(cls, value: str) -> str:
    #     """Validate the value of the IP V4 address."""
    #     try:
    #         IPv4Address(value)
    #     except ValueError:
    #         raise ValueError(f"Invalid IP V4 address {value}") from None
    #     return value

    def to_stix2_object(self) -> stix2.v21.IPv4Address:
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.IPv4Address(
            value=self.value,
            object_marking_refs=self.markings,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class IPV6Address(ObservableBaseModel):
    """Represent an IP address observable."""

    value: str = Field(
        description="Specifies the value of one IPv6 address.",
        min_length=1,
    )

    # @field_validator("value", mode="before")
    # @classmethod
    # def validate_value(cls, value: str) -> str:
    #     """Validate the value of the IP V4 address."""
    #     try:
    #         IPv4Address(value)
    #     except ValueError:
    #         raise ValueError(f"Invalid IP V4 address {value}") from None
    #     return value

    def to_stix2_object(self) -> stix2.v21.IPv6Address:
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.IPv6Address(
            value=self.value,
            object_marking_refs=self.markings,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class MACAddress(ObservableBaseModel):
    """Represent a MAC address observable in OpenCTI."""

    value: str = Field(
        description="Specifies the value of a single MAC address.",
        min_length=1,
    )

    def to_stix2_object(self) -> stix2.MACAddress:
        return stix2.MACAddress(
            value=self.value,
            object_marking_refs=self.markings,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class Url(ObservableBaseModel):
    """Represent a URL observable in OpenCTI."""

    value: str = Field(
        description="Specifies the value of the URL.",
        min_length=1,
    )

    def to_stix2_object(self) -> stix2.URL:
        return stix2.URL(
            value=self.value,
            object_marking_refs=self.markings,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class UserAccount(ObservableBaseModel):
    """Represent a user account observable."""

    account_login: Optional[str] = Field(
        description="Specifies the account login (what a user would type when they login).",
        min_length=1,
        default=None,
    )
    account_type: Optional[str] = Field(
        description="Specifies the type of the account.",
        min_length=1,
        default=None,
    )

    def to_stix2_object(self) -> stix2.UserAccount:
        return stix2.UserAccount(
            account_login=self.account_login,
            account_type=self.account_type,
            object_marking_refs=self.markings,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )


class UserAgent(ObservableBaseModel):
    """Represent a user agent observable (custom object)."""

    value: str = Field(
        description="Specifies the value of a user agent.",
        min_length=1,
    )

    def to_stix2_object(self) -> pycti.CustomObservableUserAgent:
        return pycti.CustomObservableUserAgent(
            value=self.value,
            object_marking_refs=self.markings,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
        )
