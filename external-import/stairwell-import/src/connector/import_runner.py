from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

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
    make_relationship,
    make_report,
    make_url,
    stairwell_identity,
)

logger = logging.getLogger(__name__)

# File hashes are the only values interpolated into STIX patterns, so a hash
# that is not exactly 64 hex characters is skipped rather than escaped: an
# invalid pattern makes OpenCTI reject the run's whole bundle.
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class StairwellImportError(Exception):
    """A run that must not commit state: the next run retries its window."""


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


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
        """Import one window of MalEval-malicious objects.

        State is a committed watermark (`last_run`) plus, while a window is
        being drained across runs, a `pending` cursor: the window's cutoff,
        its end, and the page token to resume from. The watermark advances to
        the window's end only after the last page is sent, so a capped or
        failed run never skips objects. Re-sent objects are harmless because
        every STIX id is deterministic.
        """
        run_started = datetime.now(tz=timezone.utc)
        state = self.helper.get_state() or {}
        pending = state.get("pending") if isinstance(state, dict) else None
        pending_cutoff = (
            _parse_iso(pending.get("cutoff")) if isinstance(pending, dict) else None
        )
        if pending_cutoff is not None:
            cutoff = pending_cutoff
            window_end = pending.get("window_end") or _iso(run_started)
            page_token = pending.get("page_token") or None
        else:
            cutoff = compute_cutoff(state, self.first_run_window, now=run_started)
            window_end = _iso(run_started)
            page_token = None

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
        resumed = page_token is not None
        page_num = 0

        # The cap is checked between pages, never mid-page: a resume token
        # points at a page boundary, so stopping mid-page would skip the rest
        # of that page. A run may overshoot the cap by less than one page.
        while True:
            page_num += 1
            entries, next_token = self._fetch_page(
                cel,
                page_token,
                page_num,
                state=state,
                resumed_first_page=resumed and page_num == 1,
            )
            for raw in entries:
                total_fetched += 1

                # Client-side bucket filter (server-side `in` returns 500).
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

            if not next_token:
                break
            page_token = next_token
            if total_emitted >= self.max_indicators:
                truncated = True
                break

        date_label = run_started.strftime("%Y-%m-%d")
        description_lines = [
            "Stairwell scheduled import run.",
            f"- **Cutoff window:** {_iso(cutoff)} → {window_end}",
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
            self._save_state(state, window_end)
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
                        f"This run reached "
                        f"STAIRWELL_IMPORT_MAX_INDICATORS={self.max_indicators} "
                        f"after {total_fetched} objects ({total_emitted} "
                        f"indicators emitted). The remaining objects in this "
                        f"window are imported by the next run."
                    ),
                    object_refs=[wrapper_obj["id"]],
                    tlp=self.tlp,
                )
            )

        self.helper.send_stix2_bundle(
            bundle(objects), work_id=work_id, cleanup_inconsistent_bundle=True
        )
        if truncated:
            self._save_state(
                state,
                None,
                pending={
                    "cutoff": _iso(cutoff),
                    "window_end": window_end,
                    "page_token": page_token,
                },
            )
        else:
            self._save_state(state, window_end)
        return (
            f"Stairwell import: {total_emitted} indicators emitted "
            f"(fetched {total_fetched}, truncated={truncated})."
        )

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------
    def _fetch_page(
        self,
        cel: str,
        page_token: str | None,
        page_num: int,
        state: dict[str, Any],
        resumed_first_page: bool,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Fetch one page, or raise so the run commits no state.

        A client error on the first page of a resumed cursor means the saved
        token is no longer accepted; the cursor's token is cleared so the next
        run restarts the same window from its first page.
        """
        status, data = self.client.list_objects_metadata(
            cel_filter=cel, page_size=self.page_size, page_token=page_token
        )
        if status >= 400 or not isinstance(data, dict):
            if resumed_first_page and 400 <= status < 500 and status != 429:
                # The one failure that writes state: the saved page token was
                # rejected, so keep the window but drop the token. Without
                # this the cursor would retry a dead token on every run.
                pending = dict(state.get("pending") or {})
                pending["page_token"] = None
                self._save_state(state, None, pending=pending)
            raise StairwellImportError(
                f"Stairwell list_objects_metadata returned status {status} "
                f"on page {page_num}; state not advanced."
            )
        entries = (
            data.get("objectMetadatas")
            or data.get("object_metadatas")
            or data.get("objects")
            or []
        )
        if not isinstance(entries, list):
            raise StairwellImportError(
                f"Stairwell list_objects_metadata page {page_num} has no "
                f"object list; state not advanced."
            )
        next_token = data.get("nextPageToken") or data.get("next_page_token")
        return [e for e in entries if isinstance(e, dict)], next_token or None

    # ------------------------------------------------------------------
    # Per-object STIX construction
    # ------------------------------------------------------------------
    def _build_for_object(
        self, raw: dict[str, Any], run_started: datetime
    ) -> tuple[list[dict[str, Any]], str | None]:
        sha256 = str(raw.get("sha256") or raw.get("SHA256") or "").lower()
        if not _SHA256_RE.fullmatch(sha256):
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

        # Network values extracted from the file are related observables, not
        # Indicators: they include benign infrastructure (OS update hosts,
        # public resolvers, XML namespaces), and an Indicator here would put
        # them on blocklists fed from OpenCTI at the file's confidence.
        net = raw.get("networkIndicators") or raw.get("network_indicators") or {}
        if isinstance(net, dict):
            groups = (
                (net.get("ipAddresses") or net.get("ip_addresses") or [], "ip"),
                (net.get("hostnames") or [], "hostname"),
                (net.get("urls") or [], "url"),
            )
            for values, kind in groups:
                if not isinstance(values, list):
                    continue
                for value in values:
                    if not value or not isinstance(value, str):
                        continue
                    out.extend(self._network_observable(value, kind, file_sco["id"]))

        return out, file_indicator["id"]

    def _network_observable(
        self, value: str, kind: str, file_id: str
    ) -> list[dict[str, Any]]:
        if kind == "ip":
            sco = (
                make_ipv6(value, tlp=self.tlp)
                if ":" in value
                else make_ipv4(value, tlp=self.tlp)
            )
            ui_url = self.client.ip_ui_url(value)
        elif kind == "hostname":
            value = value.lower()
            sco = make_domain(value, tlp=self.tlp)
            ui_url = self.client.hostname_ui_url(value)
        elif kind == "url":
            sco = make_url(value, tlp=self.tlp)
            ui_url = self.client.url_ui_url(value)
        else:
            return []
        sco["external_references"] = [
            make_external_reference("Stairwell", ui_url, f"Stairwell intel for {value}")
        ]
        return [
            sco,
            make_relationship(file_id, sco["id"], "related-to", tlp=self.tlp),
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

    def _save_state(
        self,
        state: dict[str, Any],
        last_run: str | None,
        pending: dict[str, Any] | None = None,
    ) -> None:
        """Persist the watermark and cursor.

        `last_run=None` keeps the committed watermark; `pending=None` drops
        the cursor (the window is fully imported).
        """
        new_state = {k: v for k, v in state.items() if k != "pending"}
        if last_run is not None:
            new_state["last_run"] = last_run
        if pending is not None:
            new_state["pending"] = pending
        try:
            self.helper.set_state(new_state)
        except Exception as exc:  # noqa: BLE001
            self.helper.log_warning(f"Failed to persist connector state: {exc}")
