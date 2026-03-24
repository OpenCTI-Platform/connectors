"""Orchestration logic for a single Checkfirst ingestion pass.

Coordinates API pagination, STIX object creation, bundle assembly, and
state persistence. On the first run it also sends a one-off infrastructure
bundle covering all known Pravda network domains and their shared hosting IP.
"""

from datetime import datetime, timezone
from urllib.parse import urlparse

from checkfirst_dataset.alternates import parse_alternates
from checkfirst_dataset.api_reader import iter_api_rows
from checkfirst_dataset.dates import DateParseError, parse_publication_date
from checkfirst_dataset.reporting import RunReport, SkipReason
from checkfirst_dataset.state import load_state_from_helper, save_state_to_helper
from connector.converter_to_stix import ConverterToStix
from connector.pravda_network import SUBDOMAIN_TO_DOMAIN
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

BUNDLE_SIZE = 1000


class BundleSendError(Exception):
    pass


def _send_infrastructure_bundle(
    helper: OpenCTIConnectorHelper, converter: ConverterToStix, work_id: str
) -> None:
    """Send a one-off bundle of known Pravda network infrastructure objects.

    Called only when starting from page 1 (first run or force_reprocess).
    Relationships per domain:
      - Campaign 2023 → attributed-to → IntrusionSet
      - Campaign 2023 → uses [first_observed] → Infrastructure
      - Infrastructure → consists-of → DomainName
      - Infrastructure → consists-of → IPv4Address (with stop_time)
      - Subdomain [first_observed] → related-to → Infrastructure
    """
    from connector.pravda_network import PRAVDA_DOMAINS, PRAVDA_IP

    objects: list = [
        converter.infrastructure_campaign,
        converter.infrastructure_campaign_attributed_to_ims,
    ]

    ip_obj = converter.create_ipv4_address(
        value=PRAVDA_IP["IP"],
        first_seen=PRAVDA_IP["first_seen"],
        last_seen=PRAVDA_IP["last_seen"],
    )
    objects.append(ip_obj)

    for entry in PRAVDA_DOMAINS:
        first_observed = entry["first_observed"]

        infra_obj = converter.create_infrastructure(
            name=entry["domain"],
            first_seen=first_observed,
        )
        objects.append(infra_obj)

        domain_obj = converter.create_domain_name(
            value=entry["domain"],
            first_seen=first_observed,
        )
        objects.append(domain_obj)

        # Campaign → uses → Infrastructure
        objects.append(
            converter.create_relationship(
                source_id=converter.infrastructure_campaign.id,
                relationship_type="uses",
                target_id=infra_obj.id,
                start_time=first_observed,
            )
        )

        # Infrastructure → consists-of → DomainName
        objects.append(
            converter.create_relationship(
                source_id=infra_obj.id,
                relationship_type="consists-of",
                target_id=domain_obj.id,
                start_time=first_observed,
            )
        )

        # Infrastructure → consists-of → IPv4Address (with temporal bounds)
        objects.append(
            converter.create_relationship(
                source_id=infra_obj.id,
                relationship_type="consists-of",
                target_id=ip_obj.id,
                start_time=first_observed,
                stop_time=PRAVDA_IP["last_seen"],
            )
        )

        # Subdomains → related-to → Infrastructure
        for subdomain in entry.get("subdomains", []):
            sub_obj = converter.create_domain_name(
                value=subdomain,
                first_seen=first_observed,
            )
            objects.append(sub_obj)
            objects.append(
                converter.create_relationship(
                    source_id=sub_obj.id,
                    relationship_type="related-to",
                    target_id=infra_obj.id,
                    start_time=first_observed,
                )
            )

    _send_bundle(helper, converter, objects, work_id)


def _send_bundle(
    helper: OpenCTIConnectorHelper,
    converter: ConverterToStix,
    objects: list,
    work_id: str,
) -> None:
    """Assemble and send a STIX bundle via the helper, deduplicating by ID."""
    seen_ids: set[str] = set()
    unique: list = []
    for obj in objects:
        if obj.id not in seen_ids:
            seen_ids.add(obj.id)
            unique.append(obj)

    stix_objects = unique + [
        converter.tlp_marking,
        converter.author,
        converter.intrusion_set,
    ]
    bundle = helper.stix2_create_bundle(stix_objects)
    helper.send_stix2_bundle(
        bundle,
        work_id=work_id,
        cleanup_inconsistent_bundle=True,
    )


def run_once(helper: OpenCTIConnectorHelper, settings: ConnectorSettings) -> None:
    """Run a single ingestion pass.

    - On first run (page 1): sends the Pravda network infrastructure bundle.
    - Fetches article data from the API endpoint.
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

        if start_page == 1:
            helper.connector_logger.info(
                "Sending Pravda network infrastructure bundle (first run)"
            )
            _send_infrastructure_bundle(helper, converter, work_id)

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
                year = published_dt.year

                # --- Per-year campaign (deterministic, cached) ---
                year_campaign, year_campaign_attributed = (
                    converter.get_campaign_for_year(year)
                )

                # --- Domain observable (extracted from article URL) ---
                article_domain = urlparse(row.url).netloc
                domain_obj = converter.create_domain_name(value=article_domain)

                # --- Infrastructure wrapping the publishing domain ---
                infra_obj = converter.create_infrastructure(
                    name=article_domain,
                    first_seen=published_dt,
                )

                # --- Channel as website (the publishing domain/subdomain) ---
                channel_website = converter.create_channel(
                    name=article_domain,
                    source_url=row.url,
                )

                # --- Source as Channel (Telegram or website origin) ---
                source_channel = converter.create_channel(
                    name=row.source_title,
                    source_url=row.source_url,
                )

                # --- Content (article) ---
                content = converter.create_media_content(
                    title=row.og_title,
                    description=row.og_description,
                    url=row.url,
                    publication_date=published_dt,
                )

                # --- Relationships ---
                # Campaign → uses → Infrastructure
                campaign_uses_infra = converter.create_relationship(
                    source_id=year_campaign.id,
                    relationship_type="uses",
                    target_id=infra_obj.id,
                )
                # Campaign → uses → Channel as website
                campaign_uses_channel = converter.create_relationship(
                    source_id=year_campaign.id,
                    relationship_type="uses",
                    target_id=channel_website.id,
                    start_time=published_dt,
                )
                # Infrastructure → consists-of → DomainName
                infra_consists_of_domain = converter.create_relationship(
                    source_id=infra_obj.id,
                    relationship_type="consists-of",
                    target_id=domain_obj.id,
                )
                # Channel as website → related-to → Infrastructure
                channel_related_to_infra = converter.create_relationship(
                    source_id=channel_website.id,
                    relationship_type="related-to",
                    target_id=infra_obj.id,
                    start_time=published_dt,
                )
                # DomainName → related-to → Channel as website
                domain_related_to_channel = converter.create_relationship(
                    source_id=domain_obj.id,
                    relationship_type="related-to",
                    target_id=channel_website.id,
                    start_time=published_dt,
                )
                # Channel as website → publishes → Content
                publishes = converter.create_relationship(
                    source_id=channel_website.id,
                    relationship_type="publishes",
                    target_id=content.id,
                    start_time=published_dt,
                )
                # Channel as website → related-to → Source as Channel
                channel_uses_source = converter.create_relationship(
                    source_id=channel_website.id,
                    relationship_type="related-to",
                    target_id=source_channel.id,
                    start_time=published_dt,
                )
                # Content → related-to → Source as Channel
                content_related_to_source = converter.create_relationship(
                    source_id=content.id,
                    relationship_type="related-to",
                    target_id=source_channel.id,
                    start_time=published_dt,
                )
                bundle_objects.extend(
                    [
                        year_campaign,
                        year_campaign_attributed,
                        domain_obj,
                        infra_obj,
                        channel_website,
                        source_channel,
                        content,
                        campaign_uses_infra,
                        campaign_uses_channel,
                        infra_consists_of_domain,
                        channel_related_to_infra,
                        domain_related_to_channel,
                        publishes,
                        channel_uses_source,
                        content_related_to_source,
                    ]
                )

                # If the article domain is a known news-pravda.com subdomain,
                # link the Channel as website to its parent pravda-XX.com domain.
                parent_domain_str = SUBDOMAIN_TO_DOMAIN.get(article_domain)
                if parent_domain_str:
                    parent_domain_obj = converter.create_domain_name(
                        value=parent_domain_str
                    )
                    bundle_objects.append(parent_domain_obj)
                    bundle_objects.append(
                        converter.create_relationship(
                            source_id=channel_website.id,
                            relationship_type="related-to",
                            target_id=parent_domain_obj.id,
                            start_time=published_dt,
                        )
                    )

                # Content → related-to → alternate URLs
                for alt in parse_alternates(row.alternates):
                    alt_url = converter.create_url(value=alt)
                    alt_rel = converter.create_relationship(
                        source_id=content.id,
                        relationship_type="related-to",
                        target_id=alt_url.id,
                        start_time=published_dt,
                    )
                    bundle_objects.extend([alt_url, alt_rel])

            except DateParseError as exc:
                report.skip(SkipReason.ROW_INVALID_PUBLICATION_DATE)
                helper.connector_logger.debug(
                    "Skip row (invalid publication date)",
                    {"row": row.row_number, "error": str(exc)},
                )
                continue
            except Exception as exc:  # noqa: BLE001
                report.skip(SkipReason.ROW_MAPPING_ERROR)
                helper.connector_logger.warning(
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
                    raise BundleSendError(exc) from exc

                state["last_page"] = current_page
                state["last_run"] = int(now.timestamp())
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
                raise BundleSendError(exc) from exc

            state["last_page"] = current_page
            state["last_run"] = int(now.timestamp())
            save_state_to_helper(helper, state)

    except BundleSendError:
        pass  # already recorded and logged
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
