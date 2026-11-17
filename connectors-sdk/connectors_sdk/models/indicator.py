"""Indicator."""

from typing import Literal

from connectors_sdk.models.associated_file import AssociatedFile
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import ExtensionDefinitionId, ExtensionType
from connectors_sdk.models.kill_chain_phase import KillChainPhase
from pycti import Indicator as PyctiIndicator
from pydantic import AwareDatetime, Field
from stix2.v21 import Indicator as Stix2Indicator


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
    main_observable_type: (
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
        | None
    ) = Field(
        default=None,
        description="Observable type. "
        "See: https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/schema/stixCyberObservable.ts#L4",
    )
    description: str | None = Field(
        default=None,
        description="Description of the indicator.",
    )
    indicator_types: list[str] | None = Field(
        default=None,
        description="Indicator types. The default OpenCTI types are: "
        "'anomalous-activity', 'anonymization', 'attribution', 'benign', 'compromised', 'malicious-activity', 'unknown'. "
        "See: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_cvhfwe3t9vuo",
    )
    platforms: list[str] | None = Field(
        default=None,
        description="Platforms. The default OpenCTI platforms are: 'windows', 'macos', 'linux', 'android'. "
        "See: https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L797",
    )
    valid_from: AwareDatetime | None = Field(
        default=None,
        description="Valid from.",
    )
    valid_until: AwareDatetime | None = Field(
        default=None,
        description="Valid until.",
    )
    kill_chain_phases: list[KillChainPhase] | None = Field(
        default=None,
        description="Kill chain phases.",
    )
    score: int | None = Field(
        default=None,
        description="Score of the indicator.",
        ge=0,
        le=100,
    )
    associated_files: list[AssociatedFile] | None = Field(
        default=None,
        description="Associated files for the indicator.",
    )

    create_observables: bool | None = Field(
        default=None,
        description="If True, observables and `based-on` relationships will be created for this "
        "indicator (Delegated to OpenCTI Platform). You can also manually define the Observable objects "
        "and use BasedOnRelationship for more granularity.",
    )

    def to_stix2_object(self) -> Stix2Indicator:
        """Make stix object."""
        custom_properties = {
            "score": self.score,
            "main_observable_type": self.main_observable_type,
        }

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
            allow_custom=True,
            # Top level only, not in the OpenCTI MITRE extension: this is the format of
            # MITRE ATT&CK STIX data, and pycti reads it before the extension.
            x_mitre_platforms=self.platforms,
            **self._merge_stix2_properties(
                self._common_stix2_properties(),
                self._custom_stix2_extensions(
                    ExtensionDefinitionId.OCTI,
                    extension_type=ExtensionType.PROPERTY_EXTENSION,
                    properties=custom_properties,
                ),
                self._deprecated_x_opencti_properties(custom_properties),
                {
                    # Top level only: the platform never exports it, it is an import option.
                    "x_opencti_create_observables": self.create_observables,
                    # Not duplicated in the extension: pycti reads files from both places
                    # and joins them, so each file would be uploaded twice.
                    "x_opencti_files": [
                        file.to_stix2_object() for file in self.associated_files or []
                    ],
                },
            ),
        )
