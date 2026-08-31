"""Converter tests for the macadress.com enrichment connector (no live OpenCTI)."""

from connector.converter_to_stix import ConverterToStix

_OBS = "mac-addr--11111111-2222-4333-8444-555555555555"


def _conv():
    return ConverterToStix(ConverterToStix.make_author(), default_score=30)


def test_author_is_organization_identity():
    author = ConverterToStix.make_author()
    assert author["type"] == "identity"
    assert author["identity_class"] == "organization"
    assert author["name"] == "macadress.com"


def test_vendor_identity_is_deterministic():
    conv = _conv()
    v1 = conv.vendor_identity("Apple, Inc.", "US")
    v2 = conv.vendor_identity("Apple, Inc.", None)
    assert v1["type"] == "identity"
    assert v1["identity_class"] == "organization"
    assert v1["created_by_ref"] == conv.author["id"]
    # Deterministic on the name, so re-enrichment upserts instead of duplicating.
    assert v1["id"] == v2["id"]


def test_relationship_shape():
    conv = _conv()
    vendor = conv.vendor_identity("Apple, Inc.", "US")
    rel = conv.relationship(_OBS, "related-to", vendor["id"], description="in a block")
    assert rel["type"] == "relationship"
    assert rel["relationship_type"] == "related-to"
    assert rel["source_ref"] == _OBS
    assert rel["target_ref"] == vendor["id"]
    assert rel["created_by_ref"] == conv.author["id"]
