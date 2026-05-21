from typing import Annotated, Literal

from connector.constants import SECTIONS
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import (
    AfterValidator,
    Field,
    HttpUrl,
    PlainSerializer,
    SecretStr,
    SerializationInfo,
    ValidationInfo,
    field_validator,
)


def parse_string_to_dict(value: str) -> dict:
    """Coerce a string into a dict and add 'grey' key"""
    value_dict = {
        x.split(":")[0].lower(): int(x.split(":")[1])
        for x in value.replace(" ", "").split(",")
    }
    value_dict["grey"] = value_dict["gray"]
    return value_dict


def pycti_dict_serializer(v: dict, info: SerializationInfo) -> str | dict:
    """Serialize a dict as a comma-separated string when the Pydantic
    serialization context requests "pycti" mode; otherwise, return the list
    unchanged.
    """
    if info.context and info.context.get("mode") == "pycti":
        return ",".join(f"{k}:{v}" for k, v in v.items())
    return v


DictFromString = Annotated[
    str,
    AfterValidator(parse_string_to_dict),
    PlainSerializer(pycti_dict_serializer, when_used="json"),
]


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseConnectorConfig` to add connector specific configuration parameters and/or defaults.
    """

    id: str = Field(
        default="kaspersky--8825ba29-8475-4e6a-95b7-9206052c0934",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="Kaspersky Enrichment",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=["StixFile", "IPv4-Addr", "Domain-Name", "Hostname", "Url"],
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )
    auto: bool = Field(
        default=True,
        description="If True, the connector will automatically import data from the API.",
    )


class KasperskyConfig(BaseConfigModel):
    """
    Define config vars specific to Kaspersky connector.
    """

    # Connector extra parameters
    api_base_url: HttpUrl = Field(
        default=HttpUrl("https://tip.kaspersky.com"),
        description="Kaspersky API base URL.",
    )

    api_key: SecretStr = Field(
        description="API key used to authenticate requests to the Kaspersky service.",
    )

    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Max TLP marking of the entity to enrich (inclusive).",
        default="TLP:AMBER",
    )

    zone_octi_score_mapping: DictFromString = Field(
        default="red:100,orange:80,yellow:60,gray:20,green:0",
        description="Zone to score mapping. Only the numerical value need to be changed if necessary. "
        "See https://tip.kaspersky.com/Help/Doc_data/en-US/AboutZones.htm for further explanations",
    )

    file_sections: str = Field(
        default="LicenseInfo,Zone,FileGeneralInfo",
        description="Sections wanted to investigate for the requested hash. "
        "LicenseInfo, Zone and FileGeneralInfo are always set, can't be disabled. "
        "Only DetectionsInfo, FileDownloadedFromUrls, Industries and FileNames are currently supported",
    )
    ipv4_sections: str = Field(
        default="LicenseInfo,Zone,IpGeneralInfo",
        description="Sections wanted to investigate for the requested IPV4. "
        "LicenseInfo, Zone and IpGeneralInfo are always set, can't be disabled. "
        "Only FilesDownloadedFromIp, HostedUrls, IpWhoIs, IpDnsResolutions and Industries are currently supported",
    )
    domain_sections: str = Field(
        default="LicenseInfo,Zone,DomainGeneralInfo",
        description="Sections wanted to investigate for the requested domain/hostname. "
        "LicenseInfo, Zone and DomainGeneralInfo are always set, can't be disabled. "
        "Only DomainDnsResolutions, FilesDownloaded, FilesAccessed and Industries are currently supported",
    )
    url_sections: str = Field(
        default="LicenseInfo,Zone,UrlGeneralInfo",
        description="Sections wanted to investigate for the requested URL. "
        "LicenseInfo, Zone and UrlGeneralInfo are always set, can't be disabled. "
        "Only FilesDownloaded, FilesAccessed and Industries are currently supported",
    )

    @field_validator(
        "file_sections",
        "ipv4_sections",
        "domain_sections",
        "url_sections",
        mode="before",
    )
    @classmethod
    def _validate_value(cls, value: str, info: ValidationInfo) -> str:
        """Validate the value of sections."""
        sections = value.replace(" ", "").split(",")
        field_constants = SECTIONS[info.field_name]

        for section in sections:
            if section not in field_constants["supported_sections"]:
                raise ValueError("Invalid file sections")

        for mandatory_section in field_constants["mandatories_sections"]:
            if mandatory_section not in value:
                value += "," + mandatory_section

        return value


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include additional configuration parameters specific to the connector.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    kaspersky: KasperskyConfig = Field(default_factory=KasperskyConfig)
