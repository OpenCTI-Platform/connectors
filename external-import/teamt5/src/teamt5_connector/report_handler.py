from datetime import datetime, timezone

from pycti import Report as pyctiReport
from stix2 import ExternalReference, Report
from teamt5_connector.base_handler import BaseHandler

# Public ThreatVision report-detail page used as a human-readable
# fallback when the listing response does not surface a ``pdf_url``. This
# mirrors the URL the previous (``reports.py``) implementation produced
# and keeps the report linkable from the OpenCTI UI even on tenants whose
# listing payload omits the direct PDF link.
_REPORT_DETAIL_BASE_URL = "https://threatvision.org/reports/detail"


class ReportHandler(BaseHandler):

    name = "Report"
    url_suffix = "/api/v2/reports"
    response_key = "reports"

    def map_bundle_reference(self, raw_bundle_ref: dict) -> dict:
        # The TeamT5 ``/api/v2/reports`` listing has historically returned
        # only the report ``alias`` (a stable slug) — never the direct
        # ``stix_url`` / ``pdf_url``; the previous ``reports.py``
        # implementation reconstructed both from the alias. Prefer the
        # field straight from the listing when the API does surface it
        # (so the connector tracks any future listing-shape change
        # automatically), and fall back to the alias-derived URL
        # otherwise so reports are not silently skipped by
        # ``BaseHandler.push_objects`` (which would have happened when
        # ``stix_url`` was ``None``) and so the ExternalReference always
        # carries a real URL.
        alias = raw_bundle_ref.get("alias", "")
        api_base_url = self.config.teamt5.api_base_url.rstrip("/")

        stix_url = raw_bundle_ref.get("stix_url")
        if not stix_url and alias:
            stix_url = f"{api_base_url}/api/v2/reports/{alias}.stix"

        pdf_url = raw_bundle_ref.get("pdf_url") or (
            f"{_REPORT_DETAIL_BASE_URL}?alias={alias}" if alias else ""
        )

        return {
            "alias": alias,
            "title": raw_bundle_ref.get("title", ""),
            "digest": raw_bundle_ref.get("digest", ""),
            "stix_url": stix_url,
            "pdf_url": pdf_url,
            "type_name": raw_bundle_ref.get("type_name", ""),
            "created_at": raw_bundle_ref.get("date", 0),
        }

    def create_additional_objects(self, stix_content: list, bundle_ref: dict) -> list:
        report_obj = self._create_report(stix_content, bundle_ref)
        return stix_content + [report_obj]

    def _create_report(self, stix_content: list, bundle_ref: dict) -> Report:
        """
        Creates a STIX2 Report Object corresponding to the Report details retrieved from
        the TeamT5 API and containing references to all objects in that bundle.

        :param stix_content: A list containing all STIX objects in the bundle.
        :param bundle_ref: A dictionary containing the mapped bundle reference data regarding the Report.
        :return: A STIX2 Report containing all information and object references.
        """

        # Drop the ExternalReference entirely if we could not produce a
        # real URL — emitting one with an empty ``url`` adds noise on
        # the platform side and breaks "click through to source" for
        # the operator. ``map_bundle_reference`` already falls back to
        # the alias-derived public URL when ``pdf_url`` is absent, so
        # the empty-string branch only fires when *neither* ``pdf_url``
        # nor ``alias`` is available — i.e. the listing payload is too
        # degraded to be useful.
        external_references = []
        pdf_url = bundle_ref.get("pdf_url")
        if pdf_url:
            external_references.append(
                ExternalReference(
                    source_name="Team T5",
                    url=pdf_url,
                    description="PDF report from Team T5",
                )
            )

        published = datetime.fromtimestamp(
            bundle_ref.get("created_at"), tz=timezone.utc
        )

        name = bundle_ref["title"]
        # ``report_types`` is a list-typed open-vocab on stix2 Report; passing a
        # bare string trips validation and produces an invalid STIX object.
        report_type = bundle_ref.get("type_name") or "report"
        report_obj = Report(
            id=pyctiReport.generate_id(name, published),
            created_by_ref=self.author.id,
            name=name,
            description=bundle_ref.get("digest", ""),
            published=published,
            object_refs=[obj.get("id") for obj in stix_content if obj.get("id")],
            external_references=external_references,
            report_types=[report_type],
            object_marking_refs=[self.tlp_ref.id],
        )
        return report_obj
