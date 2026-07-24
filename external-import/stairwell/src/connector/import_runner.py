from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator
from urllib.parse import quote

from .import_filter import build_cel_filter, compute_cutoff, normalize_min_bucket
from .stairwell import StairwellClient
from .stairwell.score import score_for_bucket
from .stix_builder import (
    bundle,
    make_based_on_relationship,
    make_domain,
    make_external_reference,
    make_file_by_sha256,
    make_grouping,
    make_indicator,
    make_ipv4,
    make_ipv6,
    make_note,
    make_report,
    make_url,
    stairwell_identity,
    stix_id,
    tlp_marking,
)

logger = logging.getLogger(__name__)


class ImportRunner:
    def __init__(
        self,
        helper,
        client: StairwellClient,
        first_run_window: timedelta,
        max_indicators: int,
        page_size: int,
        min_bucket: str,
        scope_environment: bool,
        wrapper: str,
        tlp: str,
        indicator_validity_days: int,
    ) -> None:
        self.helper = helper
        self.client = client
        self.first_run_window = first_run_window
        self.max_indicators = max(1, int(max_indicators))
        self.page_size = max(1, int(page_size))
        self.min_bucket = min_bucket
        self.allowed_buckets = set(normalize_min_bucket(min_bucket))
        self.scope_environment = scope_environment
        self.wrapper = wrapper.lower() if wrapper else "grouping"
        self.tlp = tlp
        self.indicator_validity = timedelta(days=max(1, int(indicator_validity_days)))

    # ------------------------------------------------------------------
    # Entrypoint (called by pycti scheduler)
    # ------------------------------------------------------------------
    def run(self, work_id: str | None = None) -> str:
        run_started = datetime.now(tz=timezone.utc)
        state = self.helper.get_state() or {}
        cutoff = compute_cutoff(state, self.first_run_window, now=run_started)

        cel = build_cel_filter(
            cutoff=cutoff,
            min_bucket=self.min_bucket,
            scope_environment=self.scope_environment,
        )
        self.helper.log_info(
            f"Stairwell import run: cutoff={cutoff.isoformat()} filter={cel!r}"
        )

        objects: list[dict[str, Any]] = [stairwell_identity()]
        sco_ids_seen: set[str] = set()

        total_emitted = 0
        total_fetched = 0
        total_filtered_bucket = 0
        truncated = False

        for raw in self._iter_objects(cel):
            total_fetched += 1
            if total_emitted >= self.max_indicators:
                truncated = True
                break

            # Client-side bucket filter (server-side `in` operator returns 500).
            mal_eval = raw.get("malEval") or raw.get("mal_eval") or {}
            bucket = mal_eval.get("probabilityBucket") or mal_eval.get(
                "probability_bucket"
            )
            if bucket and bucket not in self.allowed_buckets:
                total_filtered_bucket += 1
                continue

            new_objects, new_indicator_id = self._build_for_object(raw, run_started)
            if not new_indicator_id:
                continue

            for obj in new_objects:
                obj_id = obj["id"]
                if obj_id in sco_ids_seen:
                    continue
                sco_ids_seen.add(obj_id)
                objects.append(obj)
            total_emitted += 1

        date_label = run_started.strftime("%Y-%m-%d")
        description_lines = [
            f"Stairwell scheduled import run.",
            f"- **Cutoff window:** {cutoff.isoformat()} → {run_started.isoformat()}",
            f"- **CEL filter:** `{cel}`",
            f"- **Min bucket (client-side):** {self.min_bucket}",
            f"- **Objects fetched:** {total_fetched}",
            f"- **Filtered by bucket:** {total_filtered_bucket}",
            f"- **Indicators emitted:** {total_emitted}",
        ]
        if truncated:
            description_lines.append(
                f"- **Truncated:** capped at STAIRWELL_IMPORT_MAX_INDICATORS={self.max_indicators}"
            )
        description = "\n".join(description_lines)

        if total_emitted == 0:
            self.helper.log_info(
                f"Stairwell import run produced no indicators ({total_fetched} fetched, all filtered)."
            )
            self._save_state(run_started)
            return f"No indicators emitted (fetched {total_fetched})."

        # Wrap everything in a Grouping or Report.
        wrapper_obj_refs = [obj["id"] for obj in objects[1:]]  # exclude identity
        wrapper_seed = f"stairwell-daily-feed|{date_label}"
        wrapper_name = f"Stairwell daily MalEval feed — {date_label}"

        if self.wrapper == "report":
            wrapper_obj = make_report(
                seed=wrapper_seed,
                name=wrapper_name,
                object_refs=wrapper_obj_refs,
                published=run_started.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                description=description,
                tlp=self.tlp,
            )
        else:
            wrapper_obj = make_grouping(
                seed=wrapper_seed,
                name=wrapper_name,
                object_refs=wrapper_obj_refs,
                description=description,
                context="malware-analysis",
                tlp=self.tlp,
            )
        objects.append(wrapper_obj)

        if truncated:
            objects.append(
                make_note(
                    seed=f"stairwell-import-truncation|{date_label}",
                    abstract="Stairwell Import Truncation",
                    content=(
                        f"This run was truncated at "
                        f"STAIRWELL_IMPORT_MAX_INDICATORS={self.max_indicators}. "
                        f"{total_fetched} objects were fetched before truncation, "
                        f"{total_emitted} indicators emitted. Lower-confidence "
                        f"objects beyond the cap were dropped."
                    ),
                    object_refs=[wrapper_obj["id"]],
                    tlp=self.tlp,
                )
            )

        self.helper.send_stix2_bundle(
            bundle(objects), work_id=work_id, cleanup_inconsistent_bundle=True
        )
        self._save_state(run_started)
        return (
            f"Stairwell import: {total_emitted} indicators emitted "
            f"(fetched {total_fetched}, truncated={truncated})."
        )

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------
    def _iter_objects(self, cel: str) -> Iterator[dict[str, Any]]:
        page_token: str | None = None
        page_num = 0
        while True:
            page_num += 1
            status, data = self.client.list_objects_metadata(
                cel_filter=cel, page_size=self.page_size, page_token=page_token
            )
            if status >= 400 or not isinstance(data, dict):
                # Fail the run rather than returning normally: a silent return
                # makes run() treat a failed fetch as "no indicators" and still
                # advance last_run, which would permanently skip data in the
                # unfetched window. process_message catches this and leaves
                # connector state untouched, so the next run retries the window.
                raise RuntimeError(
                    f"Stairwell list_objects_metadata returned status {status} "
                    f"on page {page_num}; failing the run so connector state is "
                    f"not advanced past unfetched data."
                )
            entries = (
                data.get("objectMetadatas")
                or data.get("object_metadatas")
                or data.get("objects")
                or []
            )
            if not isinstance(entries, list):
                return
            for entry in entries:
                if isinstance(entry, dict):
                    yield entry
            page_token = data.get("nextPageToken") or data.get("next_page_token")
            if not page_token:
                return

    # ------------------------------------------------------------------
    # Per-object STIX construction
    # ------------------------------------------------------------------
    def _build_for_object(
        self, raw: dict[str, Any], run_started: datetime
    ) -> tuple[list[dict[str, Any]], str | None]:
        sha256 = raw.get("sha256") or raw.get("SHA256")
        if not sha256:
            return [], None

        sha1 = raw.get("sha1") or raw.get("SHA1")
        md5 = raw.get("md5") or raw.get("MD5")

        # Score / confidence from MalEval bucket.
        mal_eval = raw.get("malEval") or raw.get("mal_eval") or {}
        bucket = mal_eval.get("probabilityBucket") or mal_eval.get("probability_bucket")
        confidence = score_for_bucket(bucket)

        first_seen_str = (
            raw.get("stairwellFirstSeenTime")
            or raw.get("globalFirstSeenTime")
            or raw.get("uploadTime")
        )
        valid_from = self._parse_or_now(first_seen_str, run_started)
        valid_from_iso = valid_from.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        valid_until_iso = (valid_from + self.indicator_validity).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )

        ext_refs = [
            make_external_reference(
                "Stairwell",
                self.client.object_ui_url(sha256),
                f"Stairwell file detail for {sha256}",
            )
        ]

        # File SCO + indicator + based-on.
        file_sco = make_file_by_sha256(sha256, tlp=self.tlp, sha1=sha1, md5=md5)
        file_indicator = make_indicator(
            pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
            name=f"Stairwell MalEval file: {sha256[:12]}…",
            seed=f"stairwell-file-indicator|{sha256.lower()}",
            valid_from=valid_from_iso,
            valid_until=valid_until_iso,
            description=f"MalEval bucket: {bucket or 'unknown'}",
            confidence=confidence,
            external_references=ext_refs,
            tlp=self.tlp,
        )
        out: list[dict[str, Any]] = [
            file_sco,
            file_indicator,
            make_based_on_relationship(
                file_indicator["id"], file_sco["id"], tlp=self.tlp
            ),
        ]

        # Network indicators (deduped *within* this object; cross-object dedup
        # happens via STIX deterministic IDs in the run-level seen set).
        net = raw.get("networkIndicators") or raw.get("network_indicators") or {}
        if isinstance(net, dict):
            for ip in net.get("ipAddresses") or net.get("ip_addresses") or []:
                if not ip or not isinstance(ip, str):
                    continue
                out.extend(
                    self._network_indicator(
                        ip,
                        kind="ip",
                        valid_from_iso=valid_from_iso,
                        valid_until_iso=valid_until_iso,
                        confidence=confidence,
                        source_sha256=sha256,
                    )
                )
            for host in net.get("hostnames") or []:
                if not host or not isinstance(host, str):
                    continue
                out.extend(
                    self._network_indicator(
                        host.lower(),
                        kind="hostname",
                        valid_from_iso=valid_from_iso,
                        valid_until_iso=valid_until_iso,
                        confidence=confidence,
                        source_sha256=sha256,
                    )
                )
            for url in net.get("urls") or []:
                if not url or not isinstance(url, str):
                    continue
                out.extend(
                    self._network_indicator(
                        url,
                        kind="url",
                        valid_from_iso=valid_from_iso,
                        valid_until_iso=valid_until_iso,
                        confidence=confidence,
                        source_sha256=sha256,
                    )
                )

        return out, file_indicator["id"]

    def _network_indicator(
        self,
        value: str,
        kind: str,
        valid_from_iso: str,
        valid_until_iso: str,
        confidence: int | None,
        source_sha256: str,
    ) -> list[dict[str, Any]]:
        if kind == "ip":
            sco = (
                make_ipv6(value, tlp=self.tlp)
                if ":" in value
                else make_ipv4(value, tlp=self.tlp)
            )
            obs_path = (
                "ipv4-addr:value" if sco["type"] == "ipv4-addr" else "ipv6-addr:value"
            )
        elif kind == "hostname":
            sco = make_domain(value, tlp=self.tlp)
            obs_path = "domain-name:value"
        elif kind == "url":
            sco = make_url(value, tlp=self.tlp)
            obs_path = "url:value"
        else:
            return []

        ext_refs = [
            make_external_reference(
                "Stairwell",
                f"{self.client._base_url}/search?search-query={quote(value, safe='')}",
                f"Stairwell intel for {value}",
            )
        ]
        ind = make_indicator(
            pattern=f"[{obs_path} = '{value}']",
            name=f"Stairwell {kind}: {value}",
            # Do not lower-case the seed: hostnames arrive pre-normalized and IPs
            # are case-insensitive, but URL paths/queries are case-sensitive, so
            # lower-casing would collide distinct URLs onto one deterministic id.
            seed=f"stairwell-{kind}-indicator|{value}",
            valid_from=valid_from_iso,
            valid_until=valid_until_iso,
            description=f"Extracted from MalEval-true file {source_sha256}",
            confidence=confidence,
            external_references=ext_refs,
            tlp=self.tlp,
        )
        return [
            sco,
            ind,
            make_based_on_relationship(ind["id"], sco["id"], tlp=self.tlp),
        ]

    @staticmethod
    def _parse_or_now(iso_str: str | None, fallback: datetime) -> datetime:
        if not iso_str:
            return fallback
        try:
            parsed = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except (ValueError, AttributeError):
            return fallback

    def _save_state(self, run_started: datetime) -> None:
        state = self.helper.get_state() or {}
        state["last_run"] = run_started.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        try:
            self.helper.set_state(state)
        except Exception as exc:  # noqa: BLE001
            self.helper.log_warning(f"Failed to persist connector state: {exc}")
