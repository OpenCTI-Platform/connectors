# pragma: no cover # Do not compute coverage on test files
"""Offer tests for OpenCTI Models public API."""

import inspect

import connectors_sdk.models as models
import connectors_sdk.models.octi as octi

MODELS = [
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
]
FEATURE_NAMES = MODELS + [
    "related_to",
    "based_on",
    "derived_from",
    "indicates",
    "targets",
    "located_at",
    "has",
]


def test_no_public_class_are_abstract():
    """Test that no public class in __all__ are abstract except for BaseEntity for typing purpose."""
    # Given the public API of the octi module
    public_features = [
        feat
        for feat in octi.__all__
        if not feat in ["BaseEntity", "BaseIdentifiedEntity"]
    ]
    # When checking each class in the public API
    for feature_name in public_features:
        cls = getattr(octi, feature_name)
        if not inspect.isclass(cls):
            continue
        # Then it should not be an abstract class
        assert (
            not cls.__abstractmethods__
        ), f"{feature_name} should not be exposed as abstract class"


def test_public_features_are_present():
    """Test that features are not removed by mistake."""
    # Given the feature name
    # Then it should all be present
    missing = set(FEATURE_NAMES) - set(octi.__all__)
    extra = set(octi.__all__) - set(FEATURE_NAMES)
    assert not missing, f"Missing features in octi model public api: {missing}"
    assert not extra, f"Unexpected features in octi model public api: {extra}"


def test_public_models_are_present():
    """Test that features are not removed by mistake."""
    # Given the feature name
    # Then it should all be present
    missing = set(MODELS) - set(models.__all__)
    extra = set(models.__all__) - set(MODELS)
    assert not missing, f"Missing features in models model public api: {missing}"
    assert not extra, f"Unexpected features in models model public api: {extra}"
