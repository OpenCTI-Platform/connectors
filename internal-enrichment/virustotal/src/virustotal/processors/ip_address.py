import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from virustotal.models.configs.virustotal_configs import resolve_since_floor
from virustotal.processors.entity import EntityProcessor

if TYPE_CHECKING:
    from virustotal.builder import VirusTotalBuilder

# Maximum page size of the VirusTotal relationships endpoints.
_RESOLUTIONS_PAGE_SIZE = 40


class IPProcessor(EntityProcessor):
    """Enriches IPv4-Addr observables and Indicators."""

    _GTI_ENDPOINT_TYPE = "ip_addresses"

    def process(self) -> str | None:
        """Run the IP enrichment, then import the resolved domains when enabled.

        Outside playbooks, resolutions are sent page by page after the main
        bundle so results appear progressively. In a playbook, every send
        triggers the next step, so resolutions are appended to the main bundle
        and sent once.
        """
        if not self.connector.ip_add_resolutions or self.is_indicator:
            return super().process()

        json_data = self._fetch_data()
        if json_data is None:
            return None
        self._check_response(json_data)
        builder = self._make_builder(json_data)
        self._enrich(builder, json_data)
        self._enrich_gti_relationships(builder)

        if self.helper.playbook is not None:
            summary = self._import_resolutions(builder, builder.bundle.extend)
            result = builder.send_bundle()
        else:
            result = builder.send_bundle()
            summary = self._import_resolutions(builder, self._send_resolutions_page)
        return f"{result}; {summary}"

    def _fetch_data(self) -> dict:
        return self.client.get_ip_info(self.opencti_entity["observable_value"])

    def _enrich(self, builder: "VirusTotalBuilder", json_data: dict) -> None:
        if self.connector.ip_add_relationships:
            builder.create_asn_belongs_to()
            builder.create_location_located_at()

        if not self.is_indicator:
            builder.create_indicator_based_on(
                self.connector.ip_indicator_config,
                f"""[ipv4-addr:value = '{self.opencti_entity["observable_value"]}']""",
            )

        builder.create_notes()

    def _send_resolutions_page(self, objects: list) -> None:
        """Send the objects built from one resolutions page as their own bundle.

        Like the main enrichment bundle, it carries the incoming objects (the
        enriched IP and the marking definitions it references), so
        ``cleanup_inconsistent_bundle`` keeps both the relationships' target
        and the IP's markings.
        """
        incoming = list(self.stix_objects)
        if all(o["id"] != self.stix_entity["id"] for o in incoming):
            incoming.append(self.stix_entity)
        bundle_objects = [self.connector.author] + incoming + objects
        self.helper.metric.inc("record_send", len(bundle_objects))
        serialized_bundle = self.helper.stix2_create_bundle(bundle_objects)
        self.helper.send_stix2_bundle(
            serialized_bundle, cleanup_inconsistent_bundle=True
        )

    def _import_resolutions(
        self, builder: "VirusTotalBuilder", emit: Callable[[list], None]
    ) -> str:
        """Page the IP resolutions newest first and emit the kept ones per page.

        Paging stops at the first of: a resolution last seen before the date
        floor, the entry cap, the page cap, the end of the list or a failed
        page. Objects already emitted are kept whatever the stop reason.

        Parameters
        ----------
        builder : VirusTotalBuilder
            Builder of the current IP enrichment.
        emit : Callable[[list], None]
            Receives the objects built from each page.

        Returns
        -------
        str
            Summary for the work message.
        """
        ip = self.opencti_entity["observable_value"]
        floor = resolve_since_floor(
            self.connector.ip_resolutions_since, datetime.now(timezone.utc)
        )
        max_entries = self.connector.ip_resolutions_max_entries
        max_pages = self.connector.ip_resolutions_max_pages
        requests_per_minute = self.connector.api_requests_per_minute
        delay = 60 / requests_per_minute if requests_per_minute > 0 else 0
        log_context = {
            "ip": ip,
            "date_floor": floor.isoformat() if floor else None,
            "max_entries": max_entries,
            "max_pages": max_pages,
            "delay_seconds": delay,
        }
        self.helper.connector_logger.info(
            "[VirusTotal] Importing IP resolutions", log_context
        )

        fetched = kept = pages = 0
        cursor = None
        stopped = "end of list"
        while True:
            if pages >= max_pages:
                stopped = "page cap"
                break
            limit = (
                _RESOLUTIONS_PAGE_SIZE
                if max_entries is None
                else min(_RESOLUTIONS_PAGE_SIZE, max_entries - fetched)
            )
            if pages > 0 and delay:
                time.sleep(delay)

            page = self.client.get_ip_resolutions_page(ip, cursor, limit)
            if not page or "error" in page or "data" not in page:
                error = page.get("error") if isinstance(page, dict) else None
                self.helper.connector_logger.warning(
                    "[VirusTotal] IP resolutions page failed, stopping early",
                    {"ip": ip, "page": pages + 1, "error": error},
                )
                stopped = "error"
                break
            pages += 1
            # VirusTotal may send `"data": null` for an IP without resolutions.
            resolutions = page.get("data") or []
            fetched += len(resolutions)

            in_window = []
            below_floor = False
            for resolution in resolutions:
                last_seen = (resolution.get("attributes") or {}).get("date")
                if floor and last_seen is not None and last_seen < floor.timestamp():
                    below_floor = True
                    break
                in_window.append(resolution)

            objects = builder.build_resolved_domains(
                in_window, self.connector.ip_resolutions_keywords_regex
            )
            page_kept = sum(1 for o in objects if o["type"] == "domain-name")
            kept += page_kept
            if objects:
                emit(objects)
            self.helper.connector_logger.debug(
                "[VirusTotal] IP resolutions page processed",
                {
                    "ip": ip,
                    "page": pages,
                    "fetched": len(resolutions),
                    "in_window": len(in_window),
                    "kept": page_kept,
                },
            )

            cursor = (page.get("meta") or {}).get("cursor")
            if below_floor:
                stopped = "date floor"
                break
            if max_entries is not None and fetched >= max_entries:
                stopped = "entry cap"
                break
            if not cursor or not resolutions:
                stopped = "end of list"
                break

        summary = (
            f"resolutions: kept {kept} of {fetched} fetched "
            f"({pages} pages, stopped: {stopped})"
        )
        self.helper.connector_logger.info(
            "[VirusTotal] IP resolutions imported",
            {
                "ip": ip,
                "kept": kept,
                "fetched": fetched,
                "pages": pages,
                "stopped": stopped,
            },
        )
        return summary
