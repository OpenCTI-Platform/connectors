# pragma: no cover # Do not compute coverage on test files
"""Offer tests for OpenCTI Models public API."""

import connectors_sdk.models as models


def test_public_models_are_present():
    """Test that features are not removed by mistake."""
    # Given the feature name
    # Then it should all be present
    models_import = {
        "AdministrativeArea",
        "AssociatedFile",
        "AttackPattern",
        "AutonomousSystem",
        "BaseAuthorEntity",
        "BaseObject",
        "BaseIdentifiedEntity",
        "BaseIdentifiedObject",
        "BaseObservableEntity",
        "Campaign",
        "Channel",
        "City",
        "Country",
        "DomainName",
        "EmailAddress",
        "ExternalReference",
        "File",
        "Hostname",
        "Incident",
        "Individual",
        "Indicator",
        "Infrastructure",
        "IntrusionSet",
        "IPV4Address",
        "IPV6Address",
        "KillChainPhase",
        "MACAddress",
        "Malware",
        "MediaContent",
        "Note",
        "ObservedData",
        "Organization",
        "OrganizationAuthor",
        "Reference",
        "Region",
        "Relationship",
        "Report",
        "Sector",
        "Sighting",
        "Software",
        "Text",
        "ThreatActorGroup",
        "Tool",
        "TLPMarking",
        "URL",
        "UserAccount",
        "Vulnerability",
        "X509Certificate",
    }
    missing = models_import - set(models.__all__)
    extra = set(models.__all__) - models_import
    assert not missing, f"Missing features in models model public api: {missing}"
    assert not extra, f"Unexpected features in models model public api: {extra}"
