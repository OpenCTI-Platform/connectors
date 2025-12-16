import warnings

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
    "RelationshipType",
}


def test_deprecated_warnings() -> None:
    """Test that importing from the deprecated module raises a warning."""
    with warnings.catch_warnings(record=True) as w:
        # Importing the deprecated module
        import connectors_sdk.models.octi.enums as deprecated_enums_module  # noqa: F401

        # Check that a warning was raised
        assert len(w) == 1
        assert issubclass(w[-1].category, DeprecationWarning)
        assert (
            "The 'connectors_sdk.models.octi.enums' module is deprecated and will be "
            "removed in future versions. Please use 'connectors_sdk.models.enums' instead."
            == str(w[-1].message)
        )
        assert set(deprecated_enums_module.__all__) == OCTI_ENUMS


def test_permissive_enum() -> None:
    """Test that PermissiveEnum works as expected."""
    from connectors_sdk.models.octi.enums import PermissiveEnum

    class ColorEnum(PermissiveEnum):
        RED = "red"
        GREEN = "green"
        BLUE = "blue"

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
