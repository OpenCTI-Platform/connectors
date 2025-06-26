"""Model representing a Google Threat Intelligence Attack Technique."""

from typing import Dict, List, Optional, Union

from pydantic import BaseModel, Field


class Info(BaseModel):
    """Information related to the attack technique."""

    x_mitre_contributors: Optional[List[str]] = Field(
        None, description="People and organizations who have contributed to the object."
    )
    x_mitre_platforms: Optional[List[str]] = Field(
        None, description="List of platforms that apply to the technique."
    )
    x_mitre_is_subtechnique: Optional[bool] = Field(
        None, description="If true, this technique has sub-techniques."
    )
    x_mitre_permissions_required: Optional[List[str]] = Field(
        None,
        description="The lowest level of permissions required to perform the technique.",
    )
    x_mitre_version: Optional[str] = Field(
        None, description="The version of the object in format major.minor."
    )
    x_mitre_data_sources: Optional[List[str]] = Field(
        None,
        description="Sources of information that may be used to identify the action.",
    )
    x_mitre_detection: Optional[str] = Field(
        None, description="Strategies for identifying if a technique has been used."
    )
    x_mitre_effective_permissions: Optional[List[str]] = Field(
        None, description="The level of permissions the adversary will attain."
    )
    x_mitre_defense_bypassed: Optional[List[str]] = Field(
        None,
        description="List of defensive tools, methodologies, or processes the technique can bypass.",
    )
    x_mitre_remote_support: Optional[bool] = Field(
        None,
        description="If true, the technique can be used to execute something on a remote system.",
    )
    x_mitre_impact_type: Optional[Union[str, List[str]]] = Field(
        None,
        description="Denotes if the technique can be used for integrity or availability attacks.",
    )
    x_mitre_system_requirements: Optional[str] = Field(
        None,
        description="Additional information on requirements needed for the technique.",
    )
    x_mitre_tactic_type: Optional[Union[str, List[str]]] = Field(
        None, description="Tactic type of the technique."
    )
    x_mitre_deprecated: Optional[bool] = Field(
        None,
        description="Marked as deprecated. There is not a revoking technique replacing this one.",
    )
    x_mitre_old_attack_id: Optional[str] = Field(None, description="Old ATT&CK ID.")
    x_mitre_network_requirements: Optional[bool] = Field(
        None, description="Requires network to execute the technique."
    )


class AttackTechniqueModel(BaseModel):
    """Model representing a Google Threat Intelligence Attack Technique."""

    info: Optional[Info] = Field(None, description="Technique's additional info.")
    revoked: bool = Field(
        False, description="Indicates if the technique has been revoked."
    )
    name: str = Field(..., description="Technique's name.")
    creation_date: int = Field(
        ..., description="Creation date of the attack technique (UTC timestamp)."
    )
    link: Optional[str] = Field(
        None, description="URL of the technique on MITRE's website."
    )
    stix_id: Optional[str] = Field(None, description="Technique's STIX ID.")
    last_modification_date: int = Field(
        ..., description="Date when the technique was last updated (UTC timestamp)."
    )
    description: Optional[str] = Field(None, description="Technique's description.")
    private: bool = Field(
        False, description="Whether the attack technique object is private."
    )


class GTIAttackTechniqueData(BaseModel):
    """Model representing data for a GTI attack technique."""

    id: str
    type: str = Field("attack_technique")
    links: Optional[Dict[str, str]] = None
    attributes: Optional[AttackTechniqueModel] = None


class GTIAttackTechniqueResponse(BaseModel):
    """Model representing a response containing GTI attack technique data."""

    data: GTIAttackTechniqueData
