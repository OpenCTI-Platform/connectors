"""Offer observations OpenCTI entities."""

import ipaddress
from abc import ABC, abstractmethod
from typing import Any, Literal, Optional

from connectors_sdk.models.octi._common import (
    MODEL_REGISTRY,
    AssociatedFile,
    BaseIdentifiedEntity,
)
from connectors_sdk.models.octi.settings.taxonomies import KillChainPhase
from pycti import Indicator as PyctiIndicator
from pydantic import AwareDatetime, Field, field_validator
from stix2.v21 import URL as Stix2URL  # noqa: N811 # URL is not a constant but a class
from stix2.v21 import DomainName as Stix2DomainName
from stix2.v21 import Indicator as Stix2Indicator
from stix2.v21 import IPv4Address as Stix2IPv4Address
from stix2.v21 import IPv6Address as Stix2IPv6Address
from stix2.v21 import Software as Stix2Software
from stix2.v21 import _Observable as _Stix2Observable


@MODEL_REGISTRY.register
class Observable(ABC, BaseIdentifiedEntity):
    """Base class for OpenCTI Observables.

    This class must be subclassed to create specific observable types.
    """

    score: Optional[int] = Field(
        description="Score of the observable.",
        ge=0,
        le=100,
        default=None,
    )
    description: Optional[str] = Field(
        description="Description of the observable.",
        default=None,
    )
    labels: Optional[list[str]] = Field(
        description="Labels of the observable.",
        default=None,
    )

    associated_files: Optional[list["AssociatedFile"]] = Field(
        description="Associated files for the observable.",
        default=None,
    )
    create_indicator: Optional[bool] = Field(
        description="If True, an indicator and a `based-on` relationship will be created for this observable. (Delegated to OpenCTI Platform).",
        default=None,
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
            x_opencti_files=[
                file.to_stix2_object() for file in self.associated_files or []
            ],
            x_opencti_create_indicator=self.create_indicator,
        )

    @abstractmethod
    def to_stix2_object(self) -> _Stix2Observable:
        """Make stix object.

        Notes:
        - Observables do not need deterministic stix id generation. STIX python lib handles it.

        """


@MODEL_REGISTRY.register
class Indicator(BaseIdentifiedEntity):
    """Define OpenCTI Indicators.

    Examples:
        >>> my_indicator = Indicator(
        ...     name="Example Indicator",
        ...     pattern="[ipv4-addr:value = '127.0.0.1']",
        ...     pattern_type="stix",
        ...     observable_type="IPv4-Addr",
        ...     description="An example indicator for testing purposes.",
        ...     indicator_types=["malicious-activity"],
        ...     platforms=["linux"],
        ...     valid_from="2023-01-01T00:00:00+06:00",
        ...     valid_until="2023-12-31T23:59:59+06:00",
        ...     create_observables=True,
        ... )
    """

    name: str = Field(
        description="Name of the indicator.",
        min_length=1,
    )
    pattern: str = Field(
        description="Pattern. See Stix2.1 for instance: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_me3pzm77qfnf",
        min_length=1,
    )
    pattern_type: str = Field(
        description="Pattern type. The default OpenCTI pattern types are: "
        "'stix', 'eql', 'pcre', 'shodan', 'sigma', 'snort', 'spl', 'suricata', 'tanium-signal', 'yara'."
        "See : See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_9lfdvxnyofxw",
        min_length=1,
    )
    main_observable_type: Optional[
        Literal[
            "Stix-Cyber-Observable",
            "Artifact",
            "Autonomous-System",
            "Bank-Account",
            "Credential",
            "Cryptographic-Key",
            "Cryptocurrency-Wallet",
            "Directory",
            "Domain-Name",
            "Email-Addr",
            "Email-Message",
            "Email-Mime-Part-Type",
            "StixFile",
            "Hostname",
            "IPv4-Addr",
            "IPv6-Addr",
            "Mac-Addr",
            "Media-Content",
            "Mutex",
            "Network-Traffic",
            "Payment-Card",
            "Persona",
            "Phone-Number",
            "Process",
            "Software",
            "Text",
            "Tracking-Number",
            "Url",
            "User-Account",
            "User-Agent",
            "Windows-Registry-Key",
            "X509-Certificate",
        ]
    ] = Field(
        description="Observable type. "
        "See: https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/schema/stixCyberObservable.ts#L4",
        default=None,
    )
    description: Optional[str] = Field(
        description="Description of the indicator.",
        default=None,
    )
    indicator_types: Optional[list[str]] = Field(
        description="Indicator types. The default OpenCTI types are: "
        "'anomalous-activity', 'anonymization', 'attribution', 'benign', 'compromised', 'malicious-activity', 'unknown'. "
        "See: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_cvhfwe3t9vuo",
        default=None,
    )
    platforms: Optional[list[str]] = Field(
        description="Platforms. The default OpenCTI platforms are: 'windows', 'macos', 'linux', 'android'. "
        "See: https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L797",
        default=None,
    )
    valid_from: Optional[AwareDatetime] = Field(
        description="Valid from.",
        default=None,
    )
    valid_until: Optional[AwareDatetime] = Field(
        description="Valid until.",
        default=None,
    )
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(
        description="Kill chain phases.",
        default=None,
    )
    score: Optional[int] = Field(
        description="Score of the indicator.",
        ge=0,
        le=100,
        default=None,
    )
    associated_files: Optional[list[AssociatedFile]] = Field(
        description="Associated files for the indicator.",
        default=None,
    )

    create_observables: Optional[bool] = Field(
        description="If True, observables and `based-on` relationships will be created for this "
        "indicator (Delegated to OpenCTI Platform). You can also manually define the Observable objects "
        "and use BasedOnRelationship for more granularity.",
        default=None,
    )

    def to_stix2_object(self) -> Stix2Indicator:
        """Make stix object."""
        return Stix2Indicator(
            id=PyctiIndicator.generate_id(pattern=self.pattern),
            name=self.name,
            description=self.description,
            indicator_types=self.indicator_types,
            pattern_type=self.pattern_type,
            pattern=self.pattern,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            kill_chain_phases=[
                kill_chain_phase.to_stix2_object()
                for kill_chain_phase in self.kill_chain_phases or []
            ],
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            created_by_ref=self.author.id if self.author else None,
            object_marking_refs=[marking.id for marking in self.markings or []],
            allow_custom=True,
            x_opencti_score=self.score,
            x_mitre_platforms=self.platforms,
            x_opencti_main_observable_type=self.main_observable_type,
            x_opencti_create_observables=self.create_observables,
            x_opencti_files=[
                file.to_stix2_object() for file in self.associated_files or []
            ],
        )


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
    version: Optional[str] = Field(
        description="Version of the software.",
        default=None,
    )
    vendor: Optional[str] = Field(
        description="Vendor of the software.",
        default=None,
    )
    swid: Optional[str] = Field(
        description="SWID of the software.",
        default=None,
    )
    cpe: Optional[str] = Field(
        description="CPE of the software.",
        default=None,
    )
    languages: Optional[list[str]] = Field(
        description="Languages of the software.",
        default=None,
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
    import doctest

    doctest.testmod()
