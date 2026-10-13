"""Converter tests for the Metras Enrichment connector (no live OpenCTI needed)."""

from unittest.mock import MagicMock

from connector.converter_to_stix import ConverterToStix


def _conv():
    helper = MagicMock()
    helper.connect_confidence_level = 50
    return ConverterToStix(helper)


_OBS = "ipv4-addr--11111111-1111-4111-8111-111111111111"
_TGT = "identity--22222222-2222-4222-8222-222222222222"


def test_author_is_organization_identity():
    author = _conv().author_object()
    assert author["type"] == "identity"
    assert author["identity_class"] == "organization"


def test_create_note_is_deterministic_and_targets_observable():
    conv = _conv()
    n1 = conv.create_note(_OBS, "Metras fleet context", "body", labels=["metras"])
    n2 = conv.create_note(_OBS, "Metras fleet context", "body")
    assert n1["type"] == "note"
    assert n1["object_refs"] == [_OBS]
    assert "metras" in n1["labels"]
    # Deterministic on (observable, abstract) so re-enrichment updates, not duplicates.
    assert n1["id"] == n2["id"]


def test_create_system_is_system_identity_and_none_safe():
    conv = _conv()
    system = conv.create_system("HOST-1", description="endpoint os=windows")
    assert system["type"] == "identity"
    assert system["identity_class"] == "system"
    # No name -> nothing emitted (avoids empty System identities).
    assert conv.create_system(None) is None
    assert conv.create_system("") is None


def test_create_relationship_shape():
    rel = _conv().create_relationship(_OBS, "related-to", _TGT)
    assert rel["type"] == "relationship"
    assert rel["relationship_type"] == "related-to"
    assert rel["source_ref"] == _OBS
    assert rel["target_ref"] == _TGT
