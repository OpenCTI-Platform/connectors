from typing import Annotated, Literal

from pydantic import Field, PlainSerializer, PrivateAttr, SecretStr, model_validator
from virustotal.models.configs.base_settings import ConfigBaseSettings

TLPToLower = Annotated[
    Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]


class IndicatorConfig(ConfigBaseSettings):
    """Configuration for a given indicator type."""

    threshold: int
    valid_minutes: int
    detect: bool


class ConfigLoaderVirusTotal(ConfigBaseSettings):
    """Interface for loading VirusTotal dedicated configuration."""

    # Config Loader
    token: SecretStr = Field(
        description="VirusTotal API token for authentication.",
    )
    max_tlp: TLPToLower = Field(
        default="TLP:AMBER",
        description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI. "
        "Available values: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED",
    )
    replace_with_lower_score: bool = Field(
        default=True,
        description="Whether to keep the higher of the VT or existing score (false) or force the score to be updated with the VT score even if its lower than existing score (true).",
    )

    # File/Artifact specific config settings
    file_create_note_full_report: bool = Field(
        default=True,
        description="Whether or not to include the full report as a Note.",
    )
    file_upload_unseen_artifacts: bool = Field(
        default=True,
        description="Whether to upload artifacts (smaller than 32MB) that VirusTotal has no record of for analysis.",
    )
    file_import_yara: bool = Field(
        default=True,
        description="Whether or not to import Crowdsourced YARA rules.",
    )
    file_indicator_create_positives: int = Field(
        default=10,
        description="Create an indicator for File/Artifact based observables once this positive threshold is reached.",
    )
    file_indicator_valid_minutes: int = Field(
        default=2880,
        description="How long the indicator is valid for in minutes.",
    )
    file_indicator_detect: bool = Field(
        default=True,
        description="Whether or not to set detection for the indicator to true.",
    )
    _file_indicator_config: IndicatorConfig = PrivateAttr()

    # IP specific config settings
    ip_add_relationships: bool = Field(
        default=False,
        description="Whether or not to add ASN and location resolution relationships.",
    )
    ip_indicator_create_positives: int = Field(
        default=10,
        description="Create an indicator for IPv4 based observables once this positive threshold is reached.",
    )
    ip_indicator_valid_minutes: int = Field(
        default=2880,
        description="How long the indicator is valid for in minutes.",
    )
    ip_indicator_detect: bool = Field(
        default=True,
        description="Whether or not to set detection for the indicator to true.",
    )
    _ip_indicator_config: IndicatorConfig = PrivateAttr()

    # Domain specific config settings
    domain_add_relationships: bool = Field(
        default=False,
        description="Whether or not to add IP resolution relationships.",
    )
    domain_indicator_create_positives: int = Field(
        default=10,
        description="Create an indicator for Domain based observables once this positive threshold is reached.",
    )
    domain_indicator_valid_minutes: int = Field(
        default=2880,
        description="How long the indicator is valid for in minutes.",
    )
    domain_indicator_detect: bool = Field(
        default=True,
        description="Whether or not to set detection for the indicator to true.",
    )
    _domain_indicator_config: IndicatorConfig = PrivateAttr()

    # URL specific config settings
    url_upload_unseen: bool = Field(
        default=True,
        description="Whether to upload URLs that VirusTotal has no record of for analysis.",
    )
    url_indicator_create_positives: int = Field(
        default=10,
        description="Create an indicator for URL based observables once this positive threshold is reached.",
    )
    url_indicator_valid_minutes: int = Field(
        default=2880,
        description="How long the indicator is valid for in minutes.",
    )
    url_indicator_detect: bool = Field(
        default=True,
        description="Whether or not to set detection for the indicator to true.",
    )
    _url_indicator_config: IndicatorConfig = PrivateAttr()

    # Generic config settings for File, IP, Domain, URL
    include_attributes_in_note: bool = Field(
        default=False,
        description="Whether or not to include the attributes info in Note.",
    )

    @model_validator(mode="before")
    def auto_build_configs(cls, values: dict):
        """
        Automatically build configurations (File/IP/Domain/URL).
        """
        for prefix in ["file", "ip", "domain", "url"]:
            config_key = f"{prefix}_indicator_config"
            if not values.get(config_key):
                values[config_key] = IndicatorConfig(
                    threshold=values.get(f"{prefix}_indicator_create_positives", 10),
                    valid_minutes=values.get(f"{prefix}_indicator_valid_minutes", 2880),
                    detect=values.get(f"{prefix}_indicator_detect", True),
                )
        return values
