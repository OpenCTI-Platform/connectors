from __future__ import annotations

from datetime import timezone

from checkfirst_dataset.alternates import parse_alternates
from checkfirst_dataset.api_reader import iter_api_rows
from checkfirst_dataset.dates import DateParseError, parse_publication_date
from checkfirst_dataset.reporting import RunReport, SkipReason
from checkfirst_dataset.state import (
    load_state_from_helper,
    save_state_to_helper,
)
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings

BUNDLE_SIZE = 1000


def run_once(helper, settings: ConnectorSettings) -> None:
    """Run a single ingestion pass.

    - Fetches data from the API endpoint.
    - Builds STIX objects and sends them in bundles of BUNDLE_SIZE rows.
    - Updates state after each successfully sent bundle.
    """

    report = RunReport()
    converter = ConverterToStix(helper=helper, tlp_level=settings.checkfirst.tlp_level)

    # Validate API configuration
    if not settings.checkfirst.api_url:
        helper.log_error("API URL is not configured. Please set CHECKFIRST_API_URL.")
        return
    if not settings.checkfirst.api_key:
        helper.log_error("API key is not configured. Please set CHECKFIRST_API_KEY.")
        return

    work_id = None

    def _ensure_work_id():
        nonlocal work_id
        if work_id is not None:
            return
        try:
            api = getattr(helper, "api", None)
            work = getattr(api, "work", None)
            initiate = getattr(work, "initiate_work", None)
            if callable(initiate):
                try:
                    work_id = initiate(
                        settings.connector.id, "Checkfirst API ingestion"
                    )
                except TypeError:
                    work_id = initiate(settings.connector.id)
        except Exception:  # noqa: BLE001
            pass

    if settings.checkfirst.force_reprocess:
        helper.log_info(
            "Force reprocess enabled: starting from page 1."
        )
        state = {"last_page": 0}
    else:
        state = load_state_from_helper(helper)

    # Get the last processed page from state
    start_page = state.get("last_page", 0) + 1
    if start_page > 1:
        helper.log_info(f"Resuming from page {start_page}")

    def _log_debug(msg: str) -> None:
        if hasattr(helper, "log_debug"):
            helper.log_debug(msg)
        else:
            helper.log_info(msg)

    def _send_bundle(bundle_json: str) -> None:
        """Send a STIX bundle with best-effort template-aligned options."""
        _ensure_work_id()

        send_kwargs = {"cleanup_inconsistent_bundle": True}
        if work_id is not None:
            send_kwargs["work_id"] = work_id

        try:
            helper.send_stix2_bundle(bundle_json, **send_kwargs)
        except TypeError:
            helper.send_stix2_bundle(bundle_json)

    author = None
    bundle_objects: list[object] = []
    rows_in_bundle = 0
    rows_yielded = 0
    current_page = start_page

    try:
        helper.log_info(f"Fetching data from {settings.checkfirst.api_url}{settings.checkfirst.api_endpoint}")

        for row in iter_api_rows(
            config=settings.checkfirst,
            api_url=settings.checkfirst.api_url,
            api_key=settings.checkfirst.api_key,
            api_endpoint=settings.checkfirst.api_endpoint,
            start_page=start_page,
            since=settings.checkfirst.since,
            report=report,
        ):
            rows_yielded += 1
            report.rows_seen += 1

            if author is None:
                author = converter.author
                bundle_objects = []

            try:
                published_dt_parsed = parse_publication_date(
                    row.publication_date
                )
                if published_dt_parsed.tzinfo is None:
                    published_dt_parsed = published_dt_parsed.replace(
                        tzinfo=timezone.utc
                    )

                channel = converter.create_channel(
                    name=row.source_title,
                    source_url=row.source_url,
                )
                media_content = converter.create_media_content(
                    title=row.og_title,
                    description=row.og_description,
                    url=row.url,
                    publication_date=published_dt_parsed,
                )
                source_url_obj = converter.create_url(value=row.source_url)

                publishes = converter.create_relationship(
                    source_id=channel.id,
                    relationship_type="publishes",
                    target_id=media_content.id,
                    start_time=published_dt_parsed,
                )
                related_to_source = converter.create_relationship(
                    source_id=channel.id,
                    relationship_type="related-to",
                    target_id=source_url_obj.id,
                )
                ims_uses_channel = converter.create_relationship(
                    source_id=converter.intrusion_set.id,
                    relationship_type="uses",
                    target_id=channel.id,
                )
                campaign_uses_channel = converter.create_relationship(
                    source_id=converter.campaign.id,
                    relationship_type="uses",
                    target_id=channel.id,
                )

                bundle_objects.extend(
                    [
                        channel,
                        media_content,
                        source_url_obj,
                        publishes,
                        related_to_source,
                        ims_uses_channel,
                        campaign_uses_channel,
                    ]
                )

                for alt in parse_alternates(row.alternates):
                    alt_url = converter.create_url(value=alt)
                    rel = converter.create_relationship(
                        source_id=media_content.id,
                        relationship_type="related-to",
                        target_id=alt_url.id,
                    )
                    bundle_objects.extend([alt_url, rel])
            except DateParseError as exc:
                report.skip(SkipReason.ROW_INVALID_PUBLICATION_DATE)
                _log_debug(
                    f"Skip row {row.row_number} (invalid Publication Date): {exc}"
                )
                continue
            except Exception as exc:  # noqa: BLE001
                report.skip(SkipReason.ROW_MAPPING_ERROR)
                helper.log_error(
                    f"Skip row {row.row_number} (mapping error): {exc}"
                )
                continue

            report.rows_mapped += 1
            rows_in_bundle += 1

            # Track approximate current page
            if rows_yielded % BUNDLE_SIZE == 0:
                current_page = start_page + (rows_yielded // BUNDLE_SIZE)

            if rows_in_bundle >= BUNDLE_SIZE:
                try:
                    bundle_json = converter.bundle_serialize(bundle_objects)
                    helper.log_info("Checkfirst Import Connector sending bundle to queue")
                    _send_bundle(bundle_json)
                    report.bundles_sent += 1
                except Exception as exc:  # noqa: BLE001
                    report.error(SkipReason.BUNDLE_SEND_ERROR)
                    helper.log_error(
                        f"Bundle send failed: {exc}"
                    )
                    raise

                state["last_page"] = current_page
                save_state_to_helper(helper, state)

                bundle_objects = []
                rows_in_bundle = 0

        if rows_yielded == 0:
            helper.log_info(
                f"No rows fetched from API (starting page={start_page}). "
                "All data may have been processed."
            )

        if author is None:
            helper.log_info(f"Run summary: {report.to_summary()}")
            return

        # Send remaining bundle
        if rows_in_bundle > 0:
            try:
                bundle_json = converter.bundle_serialize(bundle_objects)
                helper.log_info("Checkfirst Import Connector sending bundle to queue")
                _send_bundle(bundle_json)
                report.bundles_sent += 1
            except Exception as exc:  # noqa: BLE001
                report.error(SkipReason.BUNDLE_SEND_ERROR)
                helper.log_error(f"Bundle send failed: {exc}")
                raise

            state["last_page"] = current_page
            save_state_to_helper(helper, state)

    except Exception as exc:  # noqa: BLE001
        report.error(SkipReason.API_ERROR)
        helper.log_error(f"Error fetching data from API: {exc}")
    finally:
        helper.log_info(f"Run summary: {report.to_summary()}")

        if work_id is not None:
            try:
                api = getattr(helper, "api", None)
                work = getattr(api, "work", None)
                to_processed = getattr(work, "to_processed", None)
                if callable(to_processed):
                    try:
                        to_processed(work_id, f"Completed run: {report.to_summary()}")
                    except TypeError:
                        to_processed(work_id)
            except Exception:  # noqa: BLE001
                pass
