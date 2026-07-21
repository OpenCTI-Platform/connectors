"""Tests for the CYNA STIX converter."""

from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix


@pytest.fixture
def converter():
    return ConverterToStix(helper=MagicMock())


def _types(objects):
    return [obj.type for obj in objects]


def _news_item(
    item_id="N1",
    title="Title",
    description="",
    link="",
    published="2026-01-01T00:00:00Z",
):
    return {
        "_id": item_id,
        "metadata": {
            "title": title,
            "description": description,
            "link": link,
            "published_date": published,
        },
    }


class TestHelpers:
    def test_ext_ref_without_url(self, converter):
        ref = converter._ext_ref("CTM360-CYNA", 12)
        assert ref.source_name == "CTM360-CYNA"
        assert ref.external_id == "12"

    def test_ext_ref_with_url(self, converter):
        ref = converter._ext_ref("CTM360-CYNA", "1", url="https://example.com")
        assert ref.url == "https://example.com"

    def test_get_item_id(self, converter):
        assert converter._get_item_id({"_id": "abc"}) == "abc"
        assert converter._get_item_id({}) == "unknown"

    def test_get_item_id_non_dict_returns_unknown(self, converter):
        # A non-dict item must not raise (it would otherwise escape the
        # per-item skip path and abort the whole conversion).
        assert converter._get_item_id("not-a-dict") == "unknown"
        assert converter._get_item_id(None) == "unknown"

    def test_author_uses_deterministic_id(self, converter):
        # pycti Identity.generate_id yields a deterministic identity-- id.
        assert converter.author.id.startswith("identity--")

    def test_extract_labels(self, converter):
        labels = converter._extract_labels(
            "Critical ransomware and CVE-2024-1 advisory", "phishing zero-day botnet"
        )
        assert labels[0] == "cyna"
        for expected in (
            "cve",
            "ransomware",
            "advisory",
            "phishing",
            "zero-day",
            "malware",
        ):
            assert expected in labels

    def test_extract_labels_default_only_cyna(self, converter):
        assert converter._extract_labels("plain title", "plain body") == ["cyna"]


class TestNewsToStix:
    def test_empty_returns_empty(self, converter):
        assert converter.news_to_stix([]) == []

    def test_single_item_includes_author_report_and_tlp(self, converter):
        objects = converter.news_to_stix([_news_item(title="Some news")])
        types = _types(objects)
        assert "identity" in types
        assert "report" in types
        assert "marking-definition" in types  # TLP_WHITE included

    def test_item_with_cve_creates_vulnerability_and_relationship(self, converter):
        objects = converter.news_to_stix(
            [_news_item(title="Fix CVE-2024-12345", description="patch now")]
        )
        types = _types(objects)
        assert "vulnerability" in types
        assert "relationship" in types

    def test_vulnerability_is_tlp_marked(self, converter):
        import stix2

        objects = converter.news_to_stix(
            [_news_item(title="Fix CVE-2024-12345", description="patch now")]
        )
        vuln = next(o for o in objects if o.type == "vulnerability")
        # CVE entities must carry the same TLP marking as the referencing report.
        assert vuln.object_marking_refs == [stix2.TLP_WHITE.id]

    def test_external_source_ref_added_for_http_link(self, converter):
        objects = converter.news_to_stix(
            [_news_item(link="https://news.example/article")]
        )
        report = next(o for o in objects if o.type == "report")
        sources = {ref.source_name for ref in report.external_references}
        assert "CTM360-CYNA-Source" in sources

    def test_cve_dedup_across_items(self, converter):
        items = [
            _news_item(item_id="N1", title="CVE-2024-0001 disclosed"),
            _news_item(item_id="N2", title="More on CVE-2024-0001"),
        ]
        objects = converter.news_to_stix(items)
        vulns = [o for o in objects if o.type == "vulnerability"]
        rels = [o for o in objects if o.type == "relationship"]
        assert len(vulns) == 1  # deduplicated
        assert len(rels) == 2  # one per report

    def test_report_id_is_deterministic(self, converter):
        item = _news_item(title="Stable", published="2026-03-04T18:00:00Z")
        first = converter.news_to_stix([item])
        second = converter.news_to_stix([item])
        rid1 = next(o.id for o in first if o.type == "report")
        rid2 = next(o.id for o in second if o.type == "report")
        assert rid1 == rid2

    def test_missing_id_uses_deterministic_fallback(self, converter):
        # A missing `_id` must not fall back to uuid4(): the CTM360-CYNA
        # external reference has to stay stable across re-imports.
        item = _news_item(item_id="", title="No id news")
        first = converter.news_to_stix([item])
        second = converter.news_to_stix([item])

        def _cyna_ext_id(objects):
            report = next(o for o in objects if o.type == "report")
            ref = next(
                r for r in report.external_references if r.source_name == "CTM360-CYNA"
            )
            return ref.external_id

        assert _cyna_ext_id(first) == _cyna_ext_id(second)
        assert _cyna_ext_id(first).startswith("cyna-")

    def test_missing_published_date_is_skipped(self, converter):
        # No published_date -> Report.generate_id would be non-deterministic
        # (keyed on name+published), so the item is skipped, not imported.
        objects = converter.news_to_stix([{"_id": "N1", "metadata": {"title": "x"}}])
        assert _types(objects) == ["identity"]
        assert not any(o.type == "report" for o in objects)
        converter.helper.connector_logger.warning.assert_called()

    def test_all_items_failed_returns_author_only_without_tlp(self, converter):
        # metadata=None triggers an AttributeError inside conversion -> skipped.
        objects = converter.news_to_stix([{"_id": "bad", "metadata": None}])
        types = _types(objects)
        assert types == ["identity"]
        assert "marking-definition" not in types
        converter.helper.connector_logger.warning.assert_called()

    def test_non_dict_item_is_skipped_not_fatal(self, converter):
        # A bare non-dict item in the page must be skipped (logged) rather than
        # raising out of news_to_stix and failing the whole batch.
        objects = converter.news_to_stix(["not-a-dict", _news_item(title="Valid news")])
        types = _types(objects)
        assert "report" in types  # the valid item still converts
        converter.helper.connector_logger.warning.assert_called()
