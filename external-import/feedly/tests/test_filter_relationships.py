from copy import deepcopy
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from feedly.opencti_connector.connector import FeedlyConnector

# -- Fixtures / helpers -------------------------------------------------------

MALWARE_OBJ = {
    "type": "malware",
    "id": "malware--1234",
    "name": "EvilBot",
}

INDICATOR_OBJ = {
    "type": "indicator",
    "id": "indicator--5678",
    "pattern": "[ipv4-addr:value = '1.2.3.4']",
}

RELATIONSHIP_OBJ = {
    "type": "relationship",
    "id": "relationship--aaaa",
    "relationship_type": "indicates",
    "source_ref": "indicator--5678",
    "target_ref": "malware--1234",
}

REPORT_OBJ = {
    "type": "report",
    "id": "report--bbbb",
    "name": "Test Report",
    "description": "A test report",
    "published": "2025-01-01T00:00:00Z",
    "external_references": [{"source_name": "Feedly"}],
    "object_refs": [
        "malware--1234",
        "indicator--5678",
        "relationship--aaaa",
    ],
}


def _make_bundle(*objects):
    return {"type": "bundle", "objects": list(objects)}


# -- Unit tests for _filter_relationships ------------------------------------


class TestFilterRelationships:
    def test_removes_relationship_objects(self):
        bundle = _make_bundle(
            deepcopy(MALWARE_OBJ),
            deepcopy(RELATIONSHIP_OBJ),
            deepcopy(INDICATOR_OBJ),
        )

        FeedlyConnector._filter_relationships(bundle)

        types = [o["type"] for o in bundle["objects"]]
        assert "relationship" not in types
        assert len(bundle["objects"]) == 2

    def test_cleans_object_refs_pointing_to_removed_relationships(self):
        bundle = _make_bundle(
            deepcopy(REPORT_OBJ),
            deepcopy(RELATIONSHIP_OBJ),
            deepcopy(MALWARE_OBJ),
            deepcopy(INDICATOR_OBJ),
        )

        FeedlyConnector._filter_relationships(bundle)

        report = next(o for o in bundle["objects"] if o["type"] == "report")
        assert "relationship--aaaa" not in report["object_refs"]
        assert "malware--1234" in report["object_refs"]
        assert "indicator--5678" in report["object_refs"]

    def test_leaves_non_relationship_objects_intact(self):
        malware = deepcopy(MALWARE_OBJ)
        indicator = deepcopy(INDICATOR_OBJ)
        bundle = _make_bundle(malware, deepcopy(RELATIONSHIP_OBJ), indicator)

        FeedlyConnector._filter_relationships(bundle)

        assert bundle["objects"][0] == malware
        assert bundle["objects"][1] == indicator

    def test_noop_when_no_relationships(self):
        bundle = _make_bundle(deepcopy(MALWARE_OBJ), deepcopy(INDICATOR_OBJ))
        original_count = len(bundle["objects"])

        FeedlyConnector._filter_relationships(bundle)

        assert len(bundle["objects"]) == original_count

    def test_handles_objects_without_object_refs(self):
        bundle = _make_bundle(
            deepcopy(MALWARE_OBJ),
            deepcopy(RELATIONSHIP_OBJ),
        )

        FeedlyConnector._filter_relationships(bundle)

        assert len(bundle["objects"]) == 1
        assert "object_refs" not in bundle["objects"][0]

    def test_handles_empty_bundle(self):
        bundle = _make_bundle()

        FeedlyConnector._filter_relationships(bundle)

        assert bundle["objects"] == []

    def test_removes_multiple_relationships(self):
        rel2 = {
            "type": "relationship",
            "id": "relationship--cccc",
            "relationship_type": "uses",
            "source_ref": "malware--1234",
            "target_ref": "indicator--5678",
        }
        report = deepcopy(REPORT_OBJ)
        report["object_refs"].append("relationship--cccc")

        bundle = _make_bundle(
            report,
            deepcopy(RELATIONSHIP_OBJ),
            rel2,
            deepcopy(MALWARE_OBJ),
            deepcopy(INDICATOR_OBJ),
        )

        FeedlyConnector._filter_relationships(bundle)

        types = [o["type"] for o in bundle["objects"]]
        assert types.count("relationship") == 0
        report_out = next(o for o in bundle["objects"] if o["type"] == "report")
        assert "relationship--aaaa" not in report_out["object_refs"]
        assert "relationship--cccc" not in report_out["object_refs"]
        assert len(report_out["object_refs"]) == 2


# -- Integration tests: FeedlyConnector.fetch_bundle --------------------------


def _make_fake_bundle():
    """Return a realistic bundle as StixIoCDownloader.download_all() would."""
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "report",
                "id": "report--1111",
                "name": "Threat Report",
                "description": "Some description",
                "published": "2025-06-01T00:00:00Z",
                "external_references": [{"source_name": "Feedly"}],
                "object_refs": [
                    "indicator--2222",
                    "relationship--3333",
                ],
            },
            {
                "type": "indicator",
                "id": "indicator--2222",
                "pattern": "[domain-name:value = 'evil.com']",
            },
            {
                "type": "relationship",
                "id": "relationship--3333",
                "relationship_type": "indicates",
                "source_ref": "indicator--2222",
                "target_ref": "malware--4444",
            },
            {
                "type": "malware",
                "id": "malware--4444",
                "name": "BadMalware",
            },
        ],
    }


@patch("feedly.opencti_connector.connector.FeedlySession")
@patch("feedly.opencti_connector.connector.StixIoCDownloader")
class TestFetchBundleEnableRelationships:
    def test_relationships_kept_by_default(self, mock_downloader_cls, mock_session_cls):
        mock_downloader_cls.return_value.download_all.return_value = _make_fake_bundle()
        helper = MagicMock()

        connector = FeedlyConnector("fake-key", helper)
        bundle = connector.fetch_bundle(
            "stream-1", datetime(2025, 1, 1, tzinfo=timezone.utc)
        )

        types = {o["type"] for o in bundle["objects"]}
        assert "relationship" in types

    def test_relationships_removed_when_disabled(
        self, mock_downloader_cls, mock_session_cls
    ):
        mock_downloader_cls.return_value.download_all.return_value = _make_fake_bundle()
        helper = MagicMock()

        connector = FeedlyConnector("fake-key", helper, enable_relationships=False)
        bundle = connector.fetch_bundle(
            "stream-1", datetime(2025, 1, 1, tzinfo=timezone.utc)
        )

        types = {o["type"] for o in bundle["objects"]}
        assert "relationship" not in types

    def test_object_refs_cleaned_when_relationships_disabled(
        self, mock_downloader_cls, mock_session_cls
    ):
        mock_downloader_cls.return_value.download_all.return_value = _make_fake_bundle()
        helper = MagicMock()

        connector = FeedlyConnector("fake-key", helper, enable_relationships=False)
        bundle = connector.fetch_bundle(
            "stream-1", datetime(2025, 1, 1, tzinfo=timezone.utc)
        )

        report = next(o for o in bundle["objects"] if o["type"] == "report")
        assert "relationship--3333" not in report["object_refs"]
        assert "indicator--2222" in report["object_refs"]
