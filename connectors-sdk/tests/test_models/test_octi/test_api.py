# pragma: no cover # Do not compute coverage on test files
"""Offer tests for OpenCTI Models public API."""

import inspect

import connectors_sdk.models.octi as octi

FEATURE_NAMES = [
    "AssociatedFile",
    "BasedOn",
    "BaseEntity",
    "Country",
    "DerivedFrom",
    "ExternalReference",
    "Indicator",
    "IntrusionSet",
    "IPV4Address",
    "KillChainPhase",
    "LocatedAt",
    "Organization",
    "OrganizationAuthor",
    "RelatedTo",
    "Sector",
    "Targets",
    "TLPMarking",
    "based_on",
    "located_at",
    "related_to",
    "targets",
]


def test_no_pulic_class_are_abstract():
    """Test that no public class in __all__ are abstract except for BaseEntity for typing purpose."""
    # Given the public API of the octi module
    public_features = [feat for feat in octi.__all__ if feat != "BaseEntity"]
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


def test_public_models_are_registered_to_be_rebuild():
    """Test that all public models are registered to be rebuilt."""
    # Given the MODEL_REGISTRY
    registry = octi.MODEL_REGISTRY
    # When checking each public model
    for feature_name in octi.__all__:
        feat = getattr(octi, feature_name)
        if not inspect.isclass(feat):
            continue
        if not issubclass(feat, octi.BaseEntity):
            continue
        # Then it should be registered to be rebuilt
        assert (
            feature_name in registry.models.keys()
        ), f"{feature_name} should be registered to be rebuilt"
