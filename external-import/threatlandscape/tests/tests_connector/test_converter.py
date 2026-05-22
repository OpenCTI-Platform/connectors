from unittest.mock import MagicMock

from conftest import SAMPLE_STIX_BUNDLE
from connector.converter_to_stix import ConverterToStix


def _make_converter() -> ConverterToStix:
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return ConverterToStix(helper=helper)


def test_extract_objects_returns_all_objects():
    """All objects from the bundle are returned verbatim."""
    converter = _make_converter()
    objects = converter.extract_objects(SAMPLE_STIX_BUNDLE)

    assert len(objects) == 3
    types = {obj["type"] for obj in objects}
    assert types == {"report", "threat-actor", "identity"}


def test_extract_objects_preserves_source_identity():
    """The threatlandscape.io identity object is passed through unchanged."""
    converter = _make_converter()
    objects = converter.extract_objects(SAMPLE_STIX_BUNDLE)

    identity = next(o for o in objects if o["type"] == "identity")
    assert identity["id"] == "identity--2f63f8e1-a880-4e9f-89e6-bd86c1d5939e"
    assert identity["name"] == "threatlandscape.io"


def test_extract_objects_empty_bundle():
    """A bundle with an empty objects array returns an empty list."""
    converter = _make_converter()
    objects = converter.extract_objects(
        {"id": "bundle--x", "type": "bundle", "objects": []}
    )

    assert objects == []


def test_extract_objects_missing_objects_key_returns_empty():
    """A bundle dict without an 'objects' key logs a warning and returns empty."""
    converter = _make_converter()
    objects = converter.extract_objects({"id": "bundle--x", "type": "bundle"})

    assert objects == []
    converter.helper.connector_logger.warning.assert_called_once()


def test_extract_objects_non_list_objects_returns_empty():
    """If 'objects' is not a list, the method logs a warning and returns empty."""
    converter = _make_converter()
    objects = converter.extract_objects(
        {"id": "bundle--x", "type": "bundle", "objects": None}
    )

    assert objects == []
    converter.helper.connector_logger.warning.assert_called_once()
