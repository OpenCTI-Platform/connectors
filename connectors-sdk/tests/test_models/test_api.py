# pragma: no cover # Do not compute coverage on test files
"""Offer tests for OpenCTI Models public API."""

import connectors_sdk.models as models
import connectors_sdk.models.octi as octi


def test_deprecated_imports() -> None:
    """Test that features are not removed by mistake."""
    # Given the feature name
    # Then it should all be present
    deprecated_models_octi_import = {  # Deprecated import from models.octi
        "AssociatedFile",
        "AttackPattern",
        "BaseEntity",
        "BaseIdentifiedEntity",
        "City",
        "Country",
        "DomainName",
        "ExternalReference",
        "File",
        "Individual",
        "Indicator",
        "IntrusionSet",
        "IPV4Address",
        "IPV6Address",
        "KillChainPhase",
        "Malware",
        "Note",
        "Organization",
        "OrganizationAuthor",
        "Relationship",
        "Report",
        "Sector",
        "Software",
        "ThreatActorGroup",
        "TLPMarking",
        "URL",
        "Vulnerability",
        "related_to",
        "based_on",
        "derived_from",
        "indicates",
        "targets",
        "located_at",
        "has",
    }
    missing = deprecated_models_octi_import - set(octi.__all__)
    extra = set(octi.__all__) - deprecated_models_octi_import
    assert not missing, f"Missing features in models model public api: {missing}"
    assert not extra, f"Unexpected features in models model public api: {extra}"


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
        "City",
        "Country",
        "DomainName",
        "ExternalReference",
        "File",
        "Hostname",
        "Individual",
        "Indicator",
        "IntrusionSet",
        "IPV4Address",
        "IPV6Address",
        "KillChainPhase",
        "Malware",
        "Note",
        "Organization",
        "OrganizationAuthor",
        "Region",
        "Relationship",
        "Report",
        "Sector",
        "Software",
        "ThreatActorGroup",
        "TLPMarking",
        "URL",
        "Vulnerability",
        "X509Certificate",
    }
    missing = models_import - set(models.__all__)
    extra = set(models.__all__) - models_import
    assert not missing, f"Missing features in models model public api: {missing}"
    assert not extra, f"Unexpected features in models model public api: {extra}"
