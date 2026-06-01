"""Unit tests for ``teamt5_connector.report_handler``.

Pins the URL-fallback contract added in this PR:

* ``stix_url`` / ``pdf_url`` straight from the listing payload are
  preserved when present, so the connector tracks the newer
  TeamT5 API shape automatically.
* When the listing omits ``stix_url`` the URL is reconstructed from
  ``alias`` (``<api_base_url>/api/v2/reports/<alias>.stix``) — matching
  the previous ``reports.py`` behaviour — so
  ``BaseHandler.push_objects`` does not silently skip the report.
* When the listing omits ``pdf_url`` the human-readable
  ``https://threatvision.org/reports/detail?alias=<alias>`` is used as
  the ``ExternalReference`` URL so the report stays clickable from
  the OpenCTI UI.
* When neither ``pdf_url`` nor ``alias`` is available, no
  ``ExternalReference`` is emitted (rather than producing a noisy
  one with an empty ``url``).
"""

from types import SimpleNamespace
from unittest.mock import Mock

from teamt5_connector.report_handler import ReportHandler


def _make_handler(api_base_url="https://api.threatvision.org/"):
    helper = Mock()
    helper.connector_logger = Mock()
    config = Mock()
    config.teamt5.api_base_url = api_base_url
    author = SimpleNamespace(id="identity--00000000-0000-4000-8000-000000000001")
    tlp_ref = SimpleNamespace(
        id="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    )
    return ReportHandler(
        client=Mock(),
        helper=helper,
        config=config,
        author=author,
        tlp_ref=tlp_ref,
    )


class TestMapBundleReferenceURLs:
    def test_listing_stix_url_is_preferred_when_present(self):
        handler = _make_handler()
        raw = {
            "title": "t",
            "alias": "report-1",
            "stix_url": "https://api.threatvision.org/explicit.stix",
        }

        mapped = handler.map_bundle_reference(raw)

        assert mapped["stix_url"] == "https://api.threatvision.org/explicit.stix"

    def test_missing_stix_url_falls_back_to_alias_derived(self):
        handler = _make_handler(api_base_url="https://private.teamt5.local/")
        raw = {"title": "t", "alias": "report-1"}

        mapped = handler.map_bundle_reference(raw)

        assert (
            mapped["stix_url"]
            == "https://private.teamt5.local/api/v2/reports/report-1.stix"
        )

    def test_listing_pdf_url_is_preferred_when_present(self):
        handler = _make_handler()
        raw = {
            "title": "t",
            "alias": "report-1",
            "pdf_url": "https://api.threatvision.org/explicit.pdf",
        }

        mapped = handler.map_bundle_reference(raw)

        assert mapped["pdf_url"] == "https://api.threatvision.org/explicit.pdf"

    def test_missing_pdf_url_falls_back_to_public_detail_page(self):
        handler = _make_handler()
        raw = {"title": "t", "alias": "report-1"}

        mapped = handler.map_bundle_reference(raw)

        assert (
            mapped["pdf_url"]
            == "https://threatvision.org/reports/detail?alias=report-1"
        )

    def test_no_alias_no_pdf_url_returns_empty_pdf_url(self):
        handler = _make_handler()
        raw = {"title": "t"}

        mapped = handler.map_bundle_reference(raw)

        assert mapped["pdf_url"] == ""

    def test_no_alias_no_stix_url_returns_none_stix_url(self):
        handler = _make_handler()
        raw = {"title": "t"}

        mapped = handler.map_bundle_reference(raw)

        assert mapped["stix_url"] is None


class TestCreateReportExternalReferences:
    # STIX 2.1 ``Report`` requires a non-empty ``object_refs`` list; we feed it
    # a minimal Indicator-shaped reference so the validator is happy and the
    # test focuses on the contract we actually care about (external_references /
    # report_types).
    _STUB_STIX_CONTENT = [
        {"type": "indicator", "id": "indicator--11111111-1111-4111-8111-111111111111"}
    ]

    def test_external_reference_included_when_pdf_url_present(self):
        handler = _make_handler()
        bundle_ref = {
            "title": "Sample Report",
            "digest": "summary",
            "pdf_url": "https://threatvision.org/reports/detail?alias=r1",
            "created_at": 1700000000,
            "type_name": "report",
            "alias": "r1",
        }

        report = handler._create_report(
            stix_content=self._STUB_STIX_CONTENT, bundle_ref=bundle_ref
        )

        assert len(report.external_references) == 1
        ext = report.external_references[0]
        assert ext.url == "https://threatvision.org/reports/detail?alias=r1"
        assert ext.source_name == "Team T5"

    def test_external_reference_omitted_when_pdf_url_empty(self):
        """No ExternalReference is emitted when neither pdf_url nor alias is available."""
        handler = _make_handler()
        bundle_ref = {
            "title": "Sample Report",
            "digest": "summary",
            "pdf_url": "",
            "created_at": 1700000000,
            "type_name": "report",
            "alias": "",
        }

        report = handler._create_report(
            stix_content=self._STUB_STIX_CONTENT, bundle_ref=bundle_ref
        )

        # stix2 normalises an unset external_references to a missing
        # attribute; either-or is fine — what matters is that no empty-URL
        # ExternalReference is in the bundle.
        assert getattr(report, "external_references", []) == []

    def test_report_types_wrapped_as_list(self):
        """``report_types`` must always be a list, not a bare string."""
        handler = _make_handler()
        bundle_ref = {
            "title": "Sample Report",
            "digest": "summary",
            "pdf_url": "https://example.invalid/r.pdf",
            "created_at": 1700000000,
            "type_name": "threat-report",
            "alias": "r1",
        }

        report = handler._create_report(
            stix_content=self._STUB_STIX_CONTENT, bundle_ref=bundle_ref
        )

        assert report.report_types == ["threat-report"]

    def test_report_types_defaults_when_type_name_missing(self):
        handler = _make_handler()
        bundle_ref = {
            "title": "Sample Report",
            "digest": "summary",
            "pdf_url": "https://example.invalid/r.pdf",
            "created_at": 1700000000,
            "type_name": None,
            "alias": "r1",
        }

        report = handler._create_report(
            stix_content=self._STUB_STIX_CONTENT, bundle_ref=bundle_ref
        )

        assert report.report_types == ["report"]
