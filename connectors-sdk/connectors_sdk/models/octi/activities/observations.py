"""Offer observations OpenCTI entities."""

import ipaddress
from abc import ABC, abstractmethod
from typing import Any, Literal, Optional

import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
from connectors_sdk.models.octi._common import (
    MODEL_REGISTRY,
    AssociatedFile,
    BaseIdentifiedEntity,
)
from connectors_sdk.models.octi.settings.taxonomies import KillChainPhase
from pydantic import AwareDatetime, Field, field_validator


@MODEL_REGISTRY.register
class Observable(ABC, BaseIdentifiedEntity):
    """Base class for OpenCTI Observables.

    This class must be subclassed to create specific observable types.
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

    associated_files: Optional[list["AssociatedFile"]] = Field(
        None,
        description="Associated files for the observable.",
    )
    create_indicator: Optional[bool] = Field(
        None,
        description="If True, an indicator and a `based-on` relationship will be created for this observable. (Delegated to OpenCTI Platform).",
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
    def to_stix2_object(self) -> stix2.v21._Observable:
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
        ...,
        description="Name of the indicator.",
        min_length=1,
    )
    pattern: str = Field(
        ...,
        description="Pattern. See Stix2.1 for instance : https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_me3pzm77qfnf",
        min_length=1,
    )
    pattern_type: str = Field(
        ...,
        description="Pattern type. The default OpenCTI pattern types are: 'stix', 'eql', 'pcre', 'shodan', 'sigma', 'snort', 'spl', 'suricata', 'tanium-signal', 'yara'."
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
        None,
        description="Observable type. See: https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/schema/stixCyberObservable.ts#L4",
    )
    description: Optional[str] = Field(
        None,
        description="Description of the indicator.",
    )
    indicator_types: Optional[list[str]] = Field(
        None,
        description="Indicator types. The default OpenCTI types are: 'anomalous-activity', 'anonymization', 'attribution', 'benign', 'compromised', 'malicious-activity', 'unknown'. "
        "See: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_cvhfwe3t9vuo",
    )
    platforms: Optional[list[str]] = Field(
        None,
        description="Platforms. The default OpenCTI platforms are: 'windows', 'macos', 'linux', 'android'. "
        "See: https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L797",
    )
    valid_from: Optional[AwareDatetime] = Field(
        None,
        description="Valid from.",
    )
    valid_until: Optional[AwareDatetime] = Field(
        None,
        description="Valid until.",
    )
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(
        None,
        description="Kill chain phases.",
    )
    score: Optional[int] = Field(
        None,
        description="Score of the indicator.",
        ge=0,
        le=100,
    )
    associated_files: Optional[list[AssociatedFile]] = Field(
        None,
        description="Associated files for the indicator.",
    )

    create_observables: Optional[bool] = Field(
        None,
        description="If True, observables and `based-on` relationships will be created for this indicator (Delegated to OpenCTI Platform). You can also manually define the Observable objects and use BasedOnRelationship for more granularity.",
    )

    def to_stix2_object(self) -> stix2.v21.Indicator:
        """Make stix object."""
        _id = pycti.Indicator.generate_id(pattern=self.pattern)
        return stix2.Indicator(
            id=_id,
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
            custom_properties=dict(  # noqa: C408 # No literal dict for maintainability
                x_opencti_score=self.score,
                x_mitre_platforms=self.platforms,
                x_opencti_main_observable_type=self.main_observable_type,
                x_opencti_create_observables=self.create_observables,
                x_opencti_files=[
                    file.to_stix2_object() for file in self.associated_files or []
                ],
                # unused
                x_opencti_detection=None,
            ),
            # unused
            created=None,
            modified=None,
            revoked=None,
            labels=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
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
    """

    value: str = Field(
        ...,
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

    def to_stix2_object(self) -> stix2.v21.IPv4Address:
        """Make stix object."""
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


MODEL_REGISTRY.rebuild_all()

if __name__ == "__main__":  # pragma: no cover  # Do not run coverage on doctest
    import doctest

    doctest.testmod()
