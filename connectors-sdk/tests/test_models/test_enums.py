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
    # Test known values
    assert enums.AttackMotivation("revenge") == enums.AttackMotivation.REVENGE

    # Test unknown value on SDK permissive enum implementation
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        unknown_motivation = enums.AttackMotivation("not-a-real-motivation")

    assert unknown_motivation.value == "not-a-real-motivation"
    assert str(unknown_motivation) == "not-a-real-motivation"
    assert len(caught) == 1
    assert issubclass(caught[0].category, UserWarning)
    assert (
        "Value 'not-a-real-motivation' is out of AttackMotivation defined values."
        == str(caught[0].message)
    )


def test_public_enums_are_present() -> None:
    """Test that features are not removed by mistake."""
    missing = set(ENUMS) - set(enums.__all__)
    extra = set(enums.__all__) - set(ENUMS)
    assert not missing, f"Missing features in models model public api: {missing}"
    assert not extra, f"Unexpected features in models model public api: {extra}"
