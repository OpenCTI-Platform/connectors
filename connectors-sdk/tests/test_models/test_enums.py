import warnings
from enum import StrEnum

import connectors_sdk.models.enums as enums

OCTI_ENUMS = {
    "AttackMotivation",
    "AttackResourceLevel",
    "CvssSeverity",
    "HashAlgorithm",
    "ImplementationLanguage",
    "IndustrySector",
    "LocationType",
    "MalwareCapability",
    "MalwareType",
    "NoteType",
    "OrganizationType",
    "Permission",
    "Platform",
    "ProcessorArchitecture",
    "Reliability",
    "ReportType",
    "TLPLevel",
    "ThreatActorRole",
    "ThreatActorSophistication",
    "ThreatActorTypes",
}

ENUMS = OCTI_ENUMS | {
    "AccountType",
    "ChannelType",
    "IncidentSeverity",
    "IncidentType",
    "InfrastructureType",
    "RelationshipType",
    "ToolType",
}


def test_permissive_enum() -> None:
    """Test that PermissiveEnum works as expected."""
    class ColorEnum(StrEnum):
        RED = "red"
        GREEN = "green"
        BLUE = "blue"

        @classmethod
        def _missing_(cls, value):
            _value = str(value)
            warnings.warn(
                f"Value '{_value}' is out of {cls.__name__} defined values.",
                UserWarning,
                stacklevel=3,
            )
            obj = str.__new__(cls, _value)
            obj._value_ = _value
            return obj

    # Test known values
    assert ColorEnum("red") == ColorEnum.RED
    assert ColorEnum("green") == ColorEnum.GREEN
    assert ColorEnum("blue") == ColorEnum.BLUE

    # Test unknown value
    unknown_color = ColorEnum("yellow")
    assert unknown_color.value == "yellow"
    assert str(unknown_color) == "yellow"


def test_public_enums_are_present() -> None:
    """Test that features are not removed by mistake."""
    missing = set(ENUMS) - set(enums.__all__)
    extra = set(enums.__all__) - set(ENUMS)
    assert not missing, f"Missing features in models model public api: {missing}"
    assert not extra, f"Unexpected features in models model public api: {extra}"
