import copy

from connector.article import (
    FetchError,
    extract_article,
    fetch_html,
    find_article_reference,
    html_to_text,
    judge,
)
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

STIX_EXT_OCTI = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class ReportArticleFetcherConnector:
    """
    Fetch the article behind an RSS report and write its body to the report's content.

    The trigger is the report, not its external references: an external reference is
    shared by every report that cites the same URL, and only the report created by the
    RSS ingestion should receive the article. The connector takes the one reference the
    ingestion wrote, downloads the page over plain HTTP, keeps the article body only,
    checks it is the article and longer than the report's current text, then sends the
    report back with its content filled.

    Every message from a playbook gets a bundle back, changed or not, so that the next
    step (an AI extraction for instance) runs on the report.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.settings = config.report_article_fetcher

    def _check_markings(self, opencti_entity: dict) -> None:
        tlp = None
        for marking_definition in opencti_entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        if not self.helper.check_max_tlp(
            tlp, f"TLP:{self.config.connector.max_tlp.upper()}"
        ):
            raise ValueError(
                "TLP of the report is greater than the connector's max TLP"
            )

    def _enrich(self, report: dict) -> tuple[dict | None, str]:
        """Return the report with its content filled, or None and why not."""
        extension = report.get("extensions", {}).get(STIX_EXT_OCTI, {})
        current_content = html_to_text(extension.get("content"))
        try:
            reference = find_article_reference(
                report, self.settings.match_single_reference
            )
        except ValueError as err:
            return None, f"Skipped: {err}"

        try:
            final_url, html = fetch_html(
                reference["url"],
                user_agent=self.settings.user_agent,
                timeout=self.settings.request_timeout,
                max_size=self.settings.max_download_size,
            )
        except FetchError as err:
            return None, f"Skipped: {err}"

        article = extract_article(final_url, html)
        if article is None:
            return None, "Skipped: no article body found in the page"
        verdict = judge(
            article,
            report_name=report.get("name", ""),
            current_content=current_content,
            min_length=self.settings.min_length,
            length_ratio=self.settings.length_ratio,
            min_title_similarity=self.settings.min_title_similarity,
        )
        if not verdict.accepted:
            return None, f"Skipped: {verdict.reason}"

        enriched = copy.deepcopy(report)
        enriched.setdefault("extensions", {}).setdefault(
            STIX_EXT_OCTI, {"extension_type": "property-extension"}
        )["content"] = article.html
        return enriched, f"Article written to the report: {verdict.reason}"

    def process_message(self, data: dict) -> str:
        is_playbook = not data.get("event_type")
        stix_objects = data["stix_objects"]
        report = data["stix_entity"]
        try:
            self._check_markings(data["enrichment_entity"])
            if report["type"] != "report":
                raise ValueError(f"{report['type']} is not a report")
            self.helper.connector_logger.info(
                "Fetching the article of a report",
                meta={"report_id": report["id"], "name": report.get("name")},
            )
            enriched, message = self._enrich(report)
        except Exception as err:
            if is_playbook:
                self._send_bundle(stix_objects)
            self.helper.connector_logger.warning(
                "Report not enriched",
                meta={"report_id": report["id"], "error": str(err)},
            )
            return f"Not enriched: {err}"

        self.helper.connector_logger.info(
            "Article written to the report" if enriched else "Report left unchanged",
            meta={"report_id": report["id"], "reason": message},
        )
        if enriched is not None:
            stix_objects = [
                enriched if stix_object["id"] == report["id"] else stix_object
                for stix_object in stix_objects
            ]
            self._send_bundle(stix_objects)
        elif is_playbook:
            self._send_bundle(stix_objects)
        return message

    def _send_bundle(self, stix_objects: list) -> None:
        # No cleanup_inconsistent_bundle: the report goes back as received, and
        # the cleanup would strip its object, author and marking references
        # whose objects are not in the bundle.
        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(bundle)

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
