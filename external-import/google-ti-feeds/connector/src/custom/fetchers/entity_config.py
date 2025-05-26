"""Configuration classes for generic entity fetchers.

This module defines configuration classes that specify the differences between
various entity types (malware families, threat actors, etc.) allowing for
a single generic fetcher implementation.
"""

from dataclasses import dataclass
from typing import Any, Type

from connector.src.custom.exceptions import (
    GTIActorFetchError,
    GTIApiError,
    GTIMalwareFetchError,
    GTITechniqueFetchError,
    GTIVulnerabilityFetchError,
)
from connector.src.custom.models.gti_reports.gti_attack_technique_model import (
    GTIAttackTechniqueResponse,
)
from connector.src.custom.models.gti_reports.gti_malware_family_model import (
    GTIMalwareFamilyResponse,
)
from connector.src.custom.models.gti_reports.gti_threat_actor_model import (
    GTIThreatActorResponse,
)
from connector.src.custom.models.gti_reports.gti_vulnerability_model import (
    GTIVulnerabilityResponse,
)


@dataclass
class EntityFetcherConfig:
    """Configuration for a specific entity type fetcher."""

    entity_type: str
    relationship_type: str
    endpoint_template: str
    response_model: Type[Any]
    exception_class: Type[GTIApiError]
    display_name: str
    display_name_singular: str


MALWARE_FAMILY_CONFIG = EntityFetcherConfig(
    entity_type="malware_families",
    relationship_type="malware_families",
    endpoint_template="/collections/{entity_id}",
    response_model=GTIMalwareFamilyResponse,
    exception_class=GTIMalwareFetchError,
    display_name="malware families",
    display_name_singular="malware family",
)

THREAT_ACTOR_CONFIG = EntityFetcherConfig(
    entity_type="threat_actors",
    relationship_type="threat_actors",
    endpoint_template="/collections/{entity_id}",
    response_model=GTIThreatActorResponse,
    exception_class=GTIActorFetchError,
    display_name="threat actors",
    display_name_singular="threat actor",
)

ATTACK_TECHNIQUE_CONFIG = EntityFetcherConfig(
    entity_type="attack_techniques",
    relationship_type="attack_techniques",
    endpoint_template="/attack_techniques/{entity_id}",
    response_model=GTIAttackTechniqueResponse,
    exception_class=GTITechniqueFetchError,
    display_name="attack techniques",
    display_name_singular="attack technique",
)

VULNERABILITY_CONFIG = EntityFetcherConfig(
    entity_type="vulnerabilities",
    relationship_type="vulnerabilities",
    endpoint_template="/collections/{entity_id}",
    response_model=GTIVulnerabilityResponse,
    exception_class=GTIVulnerabilityFetchError,
    display_name="vulnerabilities",
    display_name_singular="vulnerability",
)


ENTITY_CONFIGS = {
    "malware_families": MALWARE_FAMILY_CONFIG,
    "threat_actors": THREAT_ACTOR_CONFIG,
    "attack_techniques": ATTACK_TECHNIQUE_CONFIG,
    "vulnerabilities": VULNERABILITY_CONFIG,
}
