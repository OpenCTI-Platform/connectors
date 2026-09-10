import math
import sys
from datetime import datetime, timezone
from typing import Optional

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from greedybear_client import GreedyBearClient
from pycti import OpenCTIConnectorHelper


class GreedyBearConnector:
    """
    OpenCTI External-Import connector for GreedyBear honeypot threat intelligence.

    Run order each cycle:
      1. Advanced feed (/api/feeds/advanced/) - enriched IoCs with ASN, country, reputation
      2. Fallback to standard feed if advanced returns nothing (e.g. no auth / old version)
      3. ASN aggregated feed (/api/feeds/asn/) - adds AS-level honeypot relationships
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        raw_key = self.config.greedybear.api_key
        self.client = GreedyBearClient(
            helper=self.helper,
            base_url=self.config.greedybear.api_base_url,
            api_key=raw_key.get_secret_value() if raw_key else None,
        )
        self.converter = ConverterToStix(
            helper=self.helper,
            tlp_level=self.config.greedybear.tlp_level,
            operator_name=self.config.greedybear.operator_name,
            operator_description=self.config.greedybear.operator_description,
            operator_url=self.config.greedybear.operator_url,
        )

    def _effective_max_age(self, now: datetime, last_run: Optional[str]) -> int:
        """
        Derive max_age in days from the last run timestamp.
        Returns at least 1 (GreedyBear minimum) and at most cfg.max_age.
        On first run the configured default is used as-is.
        """
        cfg = self.config.greedybear
        if not last_run:
            return cfg.max_age
        try:
            last_dt = datetime.fromisoformat(last_run)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
            elapsed_days = (now - last_dt).total_seconds() / 86400
            # Round up so a 5-minute run still covers its window; cap at cfg.max_age
            return max(1, min(cfg.max_age, math.ceil(elapsed_days)))
        except (ValueError, TypeError):
            return cfg.max_age

    def _collect_intelligence(self, now: datetime, last_run: Optional[str]) -> list:
        stix_objects = []
        cfg = self.config.greedybear
        max_age = self._effective_max_age(now, last_run)

        self.helper.connector_logger.info(
            "[GREEDYBEAR] Effective max_age", {"days": max_age}
        )

        # ---- 1. ASN feed first - builds the as_name cache for IoC processing ----
        # as_name comes from MaxMind GeoIP (geoip.as_org) stored server-side.
        # The advanced IoC feed returns only the ASN number; the AS name is only
        # available via the ASN aggregated endpoint (auth required).
        # Without an API key this returns [] immediately and the cache stays empty.
        self.helper.connector_logger.info("[GREEDYBEAR] Fetching ASN feed...")
        asn_entries = self.client.get_asn_feeds(
            max_age=max_age,
            feed_type=cfg.feed_type,
            attack_type=cfg.attack_type,
        )
        self.helper.connector_logger.info(
            "[GREEDYBEAR] ASN entries fetched", {"count": len(asn_entries)}
        )

        # Build lookup: asn (int) -> as_name (str)
        asn_name_cache: dict[int, str] = {
            int(e["asn"]): e.get("as_name", "")
            for e in asn_entries
            if e.get("asn") is not None
        }

        for entry in asn_entries:
            stix_objects.extend(self.converter.asn_entry_to_stix_objects(entry))

        # ---- 2. Advanced feed (authenticated, enriched) ----
        self.helper.connector_logger.info("[GREEDYBEAR] Fetching advanced feed...")
        iocs = self.client.get_advanced_feeds(
            max_age=max_age,
            feed_size=cfg.feed_size,
            min_score=cfg.min_score,
            ioc_type=cfg.ioc_type,
            feed_type=cfg.feed_type,
            attack_type=cfg.attack_type,
            include_mass_scanners=cfg.include_mass_scanners,
            include_tor_exit_nodes=cfg.include_tor_exit_nodes,
        )

        # ---- 3. Fallback: standard (public) feed ----
        if not iocs:
            # If we are authenticated, an empty advanced feed is unexpected (likely a
            # transient API error or auth issue) and the fallback yields *less* enriched
            # data - flag it loudly instead of silently degrading.
            if self.client.authenticated:
                self.helper.connector_logger.warning(
                    "[GREEDYBEAR] Advanced feed returned nothing despite an API key - "
                    "falling back to the standard feed (enriched data may be missing)."
                )
            else:
                self.helper.connector_logger.info(
                    "[GREEDYBEAR] No API key - using the public standard feed."
                )
            iocs = self.client.get_standard_feeds(
                feed_type=cfg.feed_type,
                attack_type=cfg.attack_type,
                prioritize=cfg.prioritize,
                include_mass_scanners=cfg.include_mass_scanners,
                include_tor_exit_nodes=cfg.include_tor_exit_nodes,
            )

        self.helper.connector_logger.info(
            "[GREEDYBEAR] IoCs to process", {"count": len(iocs)}
        )

        # Deduplicate by value field; enrich asn entry with cached as_name
        seen: set[str] = set()
        for ioc in iocs:
            val = ioc.get("value") or ioc.get("ip") or ioc.get("ioc") or ""
            if val in seen:
                continue
            seen.add(val)

            # Inject as_name from cache so create_asn() gets a proper name
            asn_raw = ioc.get("asn")
            if asn_raw is not None and "as_name" not in ioc:
                try:
                    ioc["as_name"] = asn_name_cache.get(int(asn_raw), "")
                except (ValueError, TypeError):
                    pass

            # Optional deep enrichment: one API call per IoC (only when enabled),
            # harvesting fields the feed does not carry.
            if cfg.deep_enrich and self.client.authenticated:
                enr = self.client.get_enrichment(val)
                if enr and enr.get("found") and isinstance(enr.get("ioc"), dict):
                    eioc = enr["ioc"]
                    for k in (
                        "destination_ports",
                        "sensors",
                        "credential_count",
                        "firehol_categories",
                        "number_of_days_seen",
                    ):
                        if eioc.get(k) is not None and ioc.get(k) is None:
                            ioc[k] = eioc[k]

            stix_objects.extend(
                self.converter.ioc_to_stix_objects(
                    ioc, create_indicators=cfg.create_indicators
                )
            )

        # Always include the author, GreedyBear tool, their relationship, and TLP marking
        if stix_objects:
            stix_objects.append(self.converter.author)
            stix_objects.append(self.converter.greedybear_tool)
            stix_objects.append(self.converter.operator_uses_greedybear)
            stix_objects.append(self.converter.tlp_marking)

        return stix_objects

    def process_message(self) -> None:
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting GreedyBear connector run...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            now = datetime.now(tz=timezone.utc)
            current_state = self.helper.get_state()

            last_run = current_state.get("last_run") if current_state else None
            if last_run:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Last run", {"last_run": last_run}
                )
            else:
                self.helper.connector_logger.info("[CONNECTOR] First run ever.")

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, "GreedyBear feed import"
            )

            try:
                stix_objects = self._collect_intelligence(now, last_run)

                if stix_objects:
                    bundle = self.helper.stix2_create_bundle(stix_objects)
                    bundles_sent = self.helper.send_stix2_bundle(
                        bundle,
                        work_id=work_id,
                        cleanup_inconsistent_bundle=True,
                    )
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Bundle sent",
                        {
                            "bundles_sent": len(bundles_sent),
                            "stix_objects": len(stix_objects),
                        },
                    )
                else:
                    self.helper.connector_logger.warning(
                        "[CONNECTOR] No STIX objects produced - nothing sent."
                    )

                current_state = self.helper.get_state() or {}
                current_state["last_run"] = now.isoformat()
                self.helper.set_state(current_state)

                message = (
                    f"GreedyBear connector run complete, last_run set to "
                    f"{now.isoformat()}"
                )
                self.helper.api.work.to_processed(work_id, message)
                self.helper.connector_logger.info(message)

            except Exception as err:
                self.helper.connector_logger.error(str(err))
                self.helper.api.work.to_processed(
                    work_id, f"Error: {str(err)}", in_error=True
                )

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Stopped.")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
