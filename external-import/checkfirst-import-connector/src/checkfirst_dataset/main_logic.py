from __future__ import annotations

from datetime import datetime, timezone

from checkfirst_dataset.alternates import parse_alternates
from checkfirst_dataset.api_reader import iter_api_rows
from checkfirst_dataset.dates import DateParseError, parse_publication_date
from checkfirst_dataset.reporting import RunReport, SkipReason
from checkfirst_dataset.state import load_state_from_helper, save_state_to_helper
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings

BUNDLE_SIZE = 1000


def _send_bundle(
    helper, converter: ConverterToStix, objects: list, work_id: str
) -> None:
    """Assemble and send a STIX bundle via the helper."""
    stix_objects = list(objects) + [
        converter.tlp_marking,
        converter.author,
        converter.intrusion_set,
        converter.campaign,
        converter.campaign_attributed_to_ims,
    ]
    bundle = helper.stix2_create_bundle(stix_objects)
    helper.send_stix2_bundle(
        bundle,
        work_id=work_id,
        cleanup_inconsistent_bundle=True,
    )


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
        helper.connector_logger.error(
            "API URL is not configured",
            {"env_var": "CHECKFIRST_API_URL"},
        )
        return
    if not settings.checkfirst.api_key:
        helper.connector_logger.error(
            "API key is not configured",
            {"env_var": "CHECKFIRST_API_KEY"},
        )
        return

    work_id: str | None = None

    try:
        if settings.checkfirst.force_reprocess:
            helper.connector_logger.info("Force reprocess enabled", {"start_page": 1})
            state = {"last_page": 0}
        else:
            state = load_state_from_helper(helper)

        start_page = state.get("last_page", 0) + 1
        if start_page > 1:
            helper.connector_logger.info(
                "Resuming from page", {"start_page": start_page}
            )

        now = datetime.now(tz=timezone.utc)
        run_name = f"{helper.connect_name} - {now.isoformat()}"
        work_id = helper.api.work.initiate_work(helper.connect_id, run_name)

        bundle_objects: list[object] = []
        rows_in_bundle = 0
        rows_yielded = 0
        current_page = start_page
        has_data = False

        api_url = f"{settings.checkfirst.api_url}{settings.checkfirst.api_endpoint}"
        helper.connector_logger.info("Fetching data from API", {"url": api_url})

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
            has_data = True

            try:
                published_dt = parse_publication_date(row.publication_date)
                if published_dt.tzinfo is None:
                    published_dt = published_dt.replace(tzinfo=timezone.utc)

                channel = converter.create_channel(
                    name=row.source_title,
                    source_url=row.source_url,
                )
                media_content = converter.create_media_content(
                    title=row.og_title,
                    description=row.og_description,
                    url=row.url,
                    publication_date=published_dt,
                )
                source_url_obj = converter.create_url(value=row.source_url)

                publishes = converter.create_relationship(
                    source_id=channel.id,
                    relationship_type="publishes",
                    target_id=media_content.id,
                    start_time=published_dt,
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
                helper.connector_logger.debug(
                    "Skip row (invalid publication date)",
                    {"row": row.row_number, "error": str(exc)},
                )
                continue
            except Exception as exc:  # noqa: BLE001
                report.skip(SkipReason.ROW_MAPPING_ERROR)
                helper.connector_logger.error(
                    "Skip row (mapping error)",
                    {"row": row.row_number, "error": str(exc)},
                )
                continue

            report.rows_mapped += 1
            rows_in_bundle += 1

            if rows_yielded % BUNDLE_SIZE == 0:
                current_page = start_page + (rows_yielded // BUNDLE_SIZE)

            if rows_in_bundle >= BUNDLE_SIZE:
                try:
                    helper.connector_logger.info(
                        "Sending bundle",
                        {"rows": rows_in_bundle, "page": current_page},
                    )
                    _send_bundle(helper, converter, bundle_objects, work_id)
                    report.bundles_sent += 1
                except Exception as exc:  # noqa: BLE001
                    report.error(SkipReason.BUNDLE_SEND_ERROR)
                    helper.connector_logger.error(
                        "Bundle send failed", {"error": str(exc)}
                    )
                    raise

                state["last_page"] = current_page
                save_state_to_helper(helper, state)
                bundle_objects = []
                rows_in_bundle = 0

        if not has_data:
            helper.connector_logger.info(
                "No rows fetched from API",
                {"start_page": start_page},
            )
            return

        # Send remaining bundle
        if rows_in_bundle > 0:
            try:
                helper.connector_logger.info(
                    "Sending final bundle",
                    {"rows": rows_in_bundle},
                )
                _send_bundle(helper, converter, bundle_objects, work_id)
                report.bundles_sent += 1
            except Exception as exc:  # noqa: BLE001
                report.error(SkipReason.BUNDLE_SEND_ERROR)
                helper.connector_logger.error("Bundle send failed", {"error": str(exc)})
                raise

            state["last_page"] = current_page
            save_state_to_helper(helper, state)

    except Exception as exc:  # noqa: BLE001
        report.error(SkipReason.API_ERROR)
        helper.connector_logger.error(
            "Error fetching data from API", {"error": str(exc)}
        )
    finally:
        summary = report.to_summary()
        helper.connector_logger.info("Run summary", {"summary": summary})
        if work_id is not None:
            helper.api.work.to_processed(work_id, summary)
