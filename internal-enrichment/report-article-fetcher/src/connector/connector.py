import base64
import copy
import queue
import threading
import time
from collections.abc import Callable

from connector.article import (
    Article,
    FetchError,
    PdfReport,
    extract_article,
    fetch_html,
    fetch_pdf,
    find_article_reference,
    find_report_pdf,
    html_to_text,
    judge,
    new_session,
    pdf_name,
    pdf_to_html,
    with_pdf,
)
from connector.settings import ConnectorSettings
from connectors_sdk import InternalEnrichmentConnector
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

    One instance is one worker: it owns its helper (queue consumer, OpenCTI clients
    and the context of the message being processed) and its HTTP session. Several
    workers never share either; see `run_workers`.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.settings = config.report_article_fetcher
        self.session = new_session(self.settings.user_agent)

    def _check_markings(self, opencti_entity: dict) -> None:
        """Refuse the report if any of its TLP markings is above the max TLP."""
        tlp_levels = [
            marking_definition["definition"]
            for marking_definition in opencti_entity.get("objectMarking") or []
            if marking_definition.get("definition_type") == "TLP"
        ]
        if not InternalEnrichmentConnector.is_entity_tlp_allowed(
            tlp_levels, self.config.connector.max_tlp
        ):
            raise ValueError(
                "TLP of the report is greater than the connector's max TLP"
            )

    def _enrich(
        self, report: dict, timings: dict | None = None
    ) -> tuple[dict | None, str]:
        """Return the report with its content filled, or None and why not.

        The duration of each step, in milliseconds, is written to `timings`.
        """
        timings = {} if timings is None else timings
        extension = report.get("extensions", {}).get(STIX_EXT_OCTI, {})
        current_content = html_to_text(extension.get("content"))
        try:
            reference = find_article_reference(
                report, self.settings.match_single_reference
            )
        except ValueError as err:
            return None, f"Skipped: {err}"

        started = time.monotonic()
        try:
            final_url, html = fetch_html(
                reference["url"],
                user_agent=self.settings.user_agent,
                timeout=self.settings.request_timeout,
                max_size=self.settings.max_download_size,
                session=self.session,
            )
        except FetchError as err:
            return None, f"Skipped: {err}"
        finally:
            timings["fetch_ms"] = _elapsed_ms(started)

        started = time.monotonic()
        article = extract_article(final_url, html)
        timings["extract_ms"] = _elapsed_ms(started)
        if article is None:
            return None, "Skipped: no article body found in the page"
        pdf = self._landing_pdf(article, final_url, timings)
        if pdf is not None:
            article = with_pdf(article, pdf)
        started = time.monotonic()
        verdict = judge(
            article,
            report_name=report.get("name", ""),
            current_content=current_content,
            min_length=self.settings.min_length,
            length_ratio=self.settings.length_ratio,
            min_title_similarity=self.settings.min_title_similarity,
        )
        timings["judge_ms"] = _elapsed_ms(started)
        if not verdict.accepted:
            return None, f"Skipped: {verdict.reason}"

        enriched = copy.deepcopy(report)
        enriched.setdefault("extensions", {}).setdefault(
            STIX_EXT_OCTI, {"extension_type": "property-extension"}
        )["content"] = article.html
        if pdf is None:
            return enriched, f"Article written to the report: {verdict.reason}"
        enriched["x_opencti_files"] = [
            *(report.get("x_opencti_files") or []),
            {
                "name": pdf.name,
                "data": base64.b64encode(pdf.data).decode("ascii"),
                "mime_type": "application/pdf",
                "no_trigger_import": True,
            },
        ]
        return enriched, (
            f"Article and its PDF report {pdf.name} written to the report:"
            f" {verdict.reason}"
        )

    def _landing_pdf(
        self, article: Article, page_url: str, timings: dict
    ) -> PdfReport | None:
        """The PDF report of a landing page, or None.

        A landing page is a short page (a summary) that links its report as a
        PDF on the same site. Any failure here (too large, not a PDF, no text)
        keeps the page alone, with one log line saying why: it never fails
        the enrichment.
        """
        if not self.settings.follow_pdf:
            return None
        if len(article.text) >= self.settings.landing_max_length:
            return None
        url = find_report_pdf(article, page_url)
        if url is None:
            return None
        started = time.monotonic()
        try:
            final_url, data = fetch_pdf(
                url,
                user_agent=self.settings.user_agent,
                timeout=self.settings.request_timeout,
                max_size=self.settings.max_pdf_size,
                session=self.session,
            )
            html, text = pdf_to_html(data)
        except (FetchError, ValueError) as err:
            self.helper.connector_logger.warning(
                "PDF report of a landing page not used, the page is kept alone",
                meta={"url": url, "reason": str(err)},
            )
            return None
        finally:
            timings["pdf_ms"] = _elapsed_ms(started)
        return PdfReport(
            url=final_url, name=pdf_name(final_url), html=html, text=text, data=data
        )

    def process_message(self, data: dict) -> str:
        started = time.monotonic()
        timings: dict = {}
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
            enriched, message = self._enrich(report, timings)
        except Exception as err:
            if is_playbook:
                self._send_bundle(stix_objects, timings)
            message = f"Not enriched: {err}"
            self._log_summary(report, "error", message, timings, started)
            return message

        if enriched is not None:
            stix_objects = [
                enriched if stix_object["id"] == report["id"] else stix_object
                for stix_object in stix_objects
            ]
            self._send_bundle(stix_objects, timings)
        elif is_playbook:
            self._send_bundle(stix_objects, timings)
        outcome = "enriched" if enriched is not None else "skipped"
        self._log_summary(report, outcome, message, timings, started)
        return message

    def _send_bundle(self, stix_objects: list, timings: dict) -> None:
        # No cleanup_inconsistent_bundle: the report goes back as received, and
        # the cleanup would strip its object, author and marking references
        # whose objects are not in the bundle.
        started = time.monotonic()
        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(bundle)
        timings["send_ms"] = _elapsed_ms(started)

    def _log_summary(
        self, report: dict, outcome: str, reason: str, timings: dict, started: float
    ) -> None:
        """One line per report: what happened, why, and where the time went."""
        level = self.settings.summary_log_level
        if level == "none":
            return
        log = getattr(self.helper.connector_logger, level)
        log(
            f"Report {outcome}",
            meta={
                "report_id": report.get("id"),
                "outcome": outcome,
                "reason": reason,
                "total_ms": _elapsed_ms(started),
                **timings,
            },
        )

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)


def _elapsed_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


def run_workers(
    settings: ConnectorSettings,
    make_helper: Callable[[], OpenCTIConnectorHelper],
) -> None:
    """Run `max_workers` workers in this process and wait for them.

    pycti keeps the context of the message being processed (playbook, work,
    draft, applicant) on the helper and consumes one message at a time per
    helper, so concurrency inside one helper would mix the contexts of two
    reports. Each worker therefore gets a helper of its own: its own queue
    consumer, OpenCTI clients and message context, exactly like a replica of
    the connector. Nothing mutable is shared between workers.

    A worker whose loop raises stops the whole process with that error, as a
    replica would exit: the orchestrator restarts it with every worker, and the
    process never keeps running with fewer consumers than configured.
    """
    workers = settings.report_article_fetcher.max_workers
    helpers = [make_helper()]
    if workers > 1:
        first = helpers[0]
        if first.listen_protocol != "AMQP":
            raise ValueError(
                "REPORT_ARTICLE_FETCHER_MAX_WORKERS above 1 requires the AMQP listen "
                "protocol: run replicas of the connector instead"
            )
        if getattr(first.metric, "activated", False):
            raise ValueError(
                "REPORT_ARTICLE_FETCHER_MAX_WORKERS above 1 cannot expose metrics "
                "(each worker would open the metrics port): run replicas instead"
            )
        helpers += [make_helper() for _ in range(workers - 1)]
    connectors = [ReportArticleFetcherConnector(settings, h) for h in helpers]
    if len(connectors) == 1:
        connectors[0].run()
        return
    finished: queue.Queue = queue.Queue()

    def work(connector: ReportArticleFetcherConnector) -> None:
        try:
            connector.run()
        except BaseException as error:  # reported to the main thread below
            finished.put(error)
        else:
            finished.put(None)

    threads = [
        threading.Thread(target=work, args=(c,), name=f"worker-{i}", daemon=True)
        for i, c in enumerate(connectors)
    ]
    for thread in threads:
        thread.start()
    for _ in threads:
        error = finished.get()
        if error is not None:
            raise RuntimeError(f"A worker stopped: {error!r}") from error
