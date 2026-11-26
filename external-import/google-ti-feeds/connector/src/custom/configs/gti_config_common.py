"""GTI configuration common utilities and constants.

This module defines common constants and utilities used across all GTI configuration modules.
"""

from typing import Annotated, ClassVar, Literal, TypeVar, get_args

from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)
from connector.src.octi.interfaces.base_config import BaseConfig
from connectors_sdk.settings.annotated_types import parse_comma_separated_list
from pydantic import BeforeValidator, Field, HttpUrl, SecretStr
from pydantic_settings import SettingsConfigDict

_Item = TypeVar("_Item")

# Same parsing as `connectors_sdk.ListFromString`, but the items are typed: with a
# `Literal` item type, the allowed values are declared in the config schema
# (`items.enum`), so the catalog deployment form can offer them.
# See: https://github.com/OpenCTI-Platform/connectors/issues/8098
#
# The `Literal` item type rejects an unknown value before any `mode="after"`
# validator runs, with a generic pydantic error. The validators of these options
# therefore run in `mode="before"` and parse the raw value themselves, so that an
# unknown value raises a GTIConfigurationError naming the option and its allowed
# values.
ListOfFromString = Annotated[list[_Item], BeforeValidator(parse_comma_separated_list)]

ReportType = Literal[
    "All",
    "Actor Profile",
    "Country Profile",
    "Cyber Physical Security Roundup",
    "Event Coverage/Implication",
    "Industry Reporting",
    "Malware Profile",
    "Net Assessment",
    "Network Activity Reports",
    "News Analysis",
    "OSINT Article",
    "Patch Report",
    "Strategic Perspective",
    "TTP Deep Dive",
    "Threat Activity Alert",
    "Threat Activity Report",
    "Trends and Forecasting",
    "Weekly Vulnerability Exploitation Report",
]
ALLOWED_REPORT_TYPES = list(get_args(ReportType))

Origin = Literal[
    "All",
    "partner",
    "crowdsourced",
    "google threat intelligence",
]
ALLOWED_ORIGINS = list(get_args(Origin))

# Sub-entity types that can be fetched for each data collection, so that customers
# can fine-tune which relationships to retrieve depending on their quota allowance.
# See: https://github.com/OpenCTI-Platform/connectors/issues/7053
ReportSubentity = Literal[
    "malware_families",
    "threat_actors",
    "attack_techniques",
    "vulnerabilities",
    "campaigns",
    "domains",
    "files",
    "urls",
    "ip_addresses",
    "software_toolkits",
]
ALLOWED_REPORT_SUBENTITIES = list(get_args(ReportSubentity))

CampaignSubentity = Literal[
    "malware_families",
    "attack_techniques",
    "vulnerabilities",
    "threat_actors",
    "domains",
    "files",
    "urls",
    "ip_addresses",
    "software_toolkits",
    "reports",
]
ALLOWED_CAMPAIGN_SUBENTITIES = list(get_args(CampaignSubentity))

ThreatActorSubentity = Literal[
    "malware_families",
    "attack_techniques",
    "vulnerabilities",
    # "campaigns",
    # "reports",
    # "domains",
    # "files",
    # "urls",
    # "ip_addresses",
    "software_toolkits",
]
ALLOWED_THREAT_ACTOR_SUBENTITIES = list(get_args(ThreatActorSubentity))

MalwareFamilySubentity = Literal[
    "threat_actors",
    "attack_techniques",
    "vulnerabilities",
    # "campaigns",
    # "reports",
    # "domains",
    # "files",
    # "urls",
    # "ip_addresses",
]
ALLOWED_MALWARE_FAMILY_SUBENTITIES = list(get_args(MalwareFamilySubentity))

VulnerabilitySubentity = Literal[
    "malware_families",
    "attack_techniques",
    "threat_actors",
    # "campaigns",
    # "reports",
    # "domains",
    # "files",
    # "urls",
    # "ip_addresses",
]
ALLOWED_VULNERABILITY_SUBENTITIES = list(get_args(VulnerabilitySubentity))

SoftwareToolkitSubentity = Literal[
    "malware_families",
    "attack_techniques",
]
ALLOWED_SOFTWARE_TOOLKIT_SUBENTITIES = list(get_args(SoftwareToolkitSubentity))

IndicatorSubentity = Literal[
    "malware_families",
    "threat_actors",
    "software_toolkits",
    "attack_techniques",
    # "campaigns",
]
ALLOWED_INDICATOR_SUBENTITIES = list(get_args(IndicatorSubentity))


def validate_origins_list(
    v: str | list[str], field_name: str, allowed_origins: list[str] | None = None
) -> list[str]:
    """Split and validate a comma-separated string into a list and validate its contents.

    Args:
        v: comma-separated string or list of values to validate
        field_name: Name of the field for error messages
        allowed_origins: list of allowed values (defaults to ALLOWED_ORIGINS)

    Returns:
        list of validated origin strings

    Raises:
        GTIConfigurationError: If validation fails

    """
    if allowed_origins is None:
        allowed_origins = ALLOWED_ORIGINS

    try:
        v = parse_comma_separated_list(v)
        if not v:
            raise GTIConfigurationError(f"At least one {field_name} must be specified.")

        invalid = set(v) - set(allowed_origins)
        if invalid:
            raise GTIConfigurationError(
                f"Invalid {field_name}: {', '.join(invalid)}. "
                f"Allowed values: {', '.join(allowed_origins)}."
            )
        return v
    except GTIConfigurationError:
        raise
    except Exception as e:
        raise GTIConfigurationError(f"Failed to validate {field_name}: {str(e)}") from e


def validate_subentities_list(
    v: str | list[str], field_name: str, allowed_subentities: list[str]
) -> list[str]:
    """Validate a list of sub-entity types against the types supported for a data collection.

    Unlike origins or report types, an empty list is a valid value: it means no
    sub-entities should be fetched for that data collection, which is useful to
    save on API quota.

    Args:
        v: comma-separated string or list of sub-entity type values to validate
        field_name: Name of the field for error messages
        allowed_subentities: list of sub-entity types supported for this data collection

    Returns:
        list of validated sub-entity type strings

    Raises:
        GTIConfigurationError: If validation fails

    """
    try:
        v = parse_comma_separated_list(v)
        invalid = sorted(set(v) - set(allowed_subentities))
        if invalid:
            raise GTIConfigurationError(
                f"Invalid {field_name}: {', '.join(invalid)}. "
                f"Allowed values: {', '.join(allowed_subentities)}."
            )
        return v
    except GTIConfigurationError:
        raise
    except Exception as e:
        raise GTIConfigurationError(f"Failed to validate {field_name}: {str(e)}") from e


def validate_report_types_list(
    v: str | list[str], field_name: str = "report type"
) -> list[str]:
    """Validate a list of report types against allowed values.

    Args:
        v: comma-separated string or list of values to validate
        field_name: Name of the field for error messages

    Returns:
        list of validated report type strings

    Raises:
        GTIConfigurationError: If validation fails

    """
    try:
        v = parse_comma_separated_list(v)
        if not v:
            raise GTIConfigurationError(f"At least one {field_name} must be specified.")

        invalid = set(v) - set(ALLOWED_REPORT_TYPES)
        if invalid:
            raise GTIConfigurationError(
                f"Invalid {field_name}: {', '.join(invalid)}. "
                f"Allowed values: {', '.join(ALLOWED_REPORT_TYPES)}."
            )
        return v
    except GTIConfigurationError:
        raise
    except Exception as e:
        raise GTIConfigurationError(f"Failed to validate {field_name}: {str(e)}") from e


class GTIBaseConfig(BaseConfig):
    """Base configuration class for GTI configurations."""

    yaml_section: ClassVar[str] = "gti"
    model_config = SettingsConfigDict(env_prefix="gti_", enable_decoding=False)

    api_key: SecretStr = Field(
        description="API key for authenticating with the Google Threat Intelligence service",
        min_length=1,
    )
    api_url: HttpUrl = Field(
        default=HttpUrl("https://www.virustotal.com/api/v3"),
        description="Base URL for the Google Threat Intelligence API",
    )
