from datetime import datetime, timezone

from pycti import Report as pyctiReport
from stix2 import ExternalReference, Report

from .BaseHandler import BaseHandler


class ReportHandler(BaseHandler):

    name = "Report"
    url_suffix = "/api/v2/reports"
    response_key = "reports"

    def map_bundle_reference(self, raw_bundle_ref: dict) -> dict:
        return {
            "title": raw_bundle_ref.get("title", ""),
            "digest": raw_bundle_ref.get("digest", ""),
            "stix_url": raw_bundle_ref.get("stix_url"),
            "pdf_url": raw_bundle_ref.get("pdf_url", ""),
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

        external_ref = ExternalReference(
            source_name="Team T5",
            url=bundle_ref["pdf_url"],
            description="PDF report from Team T5",
        )

        published = datetime.fromtimestamp(
            bundle_ref.get("created_at"), tz=timezone.utc
        )

        name = bundle_ref["title"]
        report_obj = Report(
            id=pyctiReport.generate_id(name, published),
            created_by_ref=self.author.id,
            name=name,
            description=bundle_ref.get("digest", ""),
            published=published,
            object_refs=[obj.get("id", None) for obj in stix_content],
            external_references=[external_ref],
            report_types=bundle_ref.get("type_name", "report"),
            object_marking_refs=[self.tlp_ref.id],
        )
        return report_obj
