from pydantic import Field, PositiveInt
from src.models.configs import ConfigBaseSettings

MITRE_ENTERPRISE_FILE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
MITRE_MOBILE_ATTACK_FILE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"
MITRE_ICS_ATTACK_FILE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
MITRE_CAPEC_FILE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
)


class _ConfigLoaderMitre(ConfigBaseSettings):
    """Interface for loading dedicated configuration."""

    # Config Loader
    remove_statement_marking: bool = Field(
        default=False,
        description=(
            "Whether to remove statement markings from the ingested MITRE data. "
            "Useful when marking metadata is unnecessary or interferes with processing."
        ),
    )
    interval: PositiveInt = Field(
        default=7,
        description=(
            "Polling interval in days for fetching and refreshing MITRE data. "
            "Determines how often the system checks for updates to ATT&CK datasets."
        ),
    )
    enterprise_file_url: str = Field(
        default=MITRE_ENTERPRISE_FILE_URL,
        description=(
            "URL to the MITRE ATT&CK Enterprise JSON file. "
            "This dataset includes tactics, techniques, and procedures (TTPs) "
            "for enterprise IT environments."
        ),
    )
    mobile_attack_file_url: str = Field(
        default=MITRE_MOBILE_ATTACK_FILE_URL,
        description=(
            "URL to the MITRE Mobile ATT&CK JSON file. "
            "Contains mobile-specific attack techniques and mappings."
        ),
    )
    ics_attack_file_url: str = Field(
        default=MITRE_ICS_ATTACK_FILE_URL,
        description=(
            "URL to the MITRE ICS ATT&CK JSON file. "
            "Pertains to attack techniques targeting industrial control systems."
        ),
    )
    capec_file_url: str = Field(
        default=MITRE_CAPEC_FILE_URL,
        description=(
            "URL to the CAPEC (Common Attack Pattern Enumeration and Classification) JSON file. "
            "Provides a comprehensive dictionary of known attack patterns used by adversaries."
        ),
    )
