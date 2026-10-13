from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from connector.import_filter import (
    build_cel_filter,
    normalize_min_bucket,
    parse_iso_duration,
    window_start,
)
from connector.stairwell import StairwellClient
from connector.stairwell.score import score_for_bucket
from connector.stix_builder import (
    make_based_on_relationship,
    make_domain,
    make_external_reference,
    make_file_by_sha256,
    make_grouping,
    make_indicator,
    make_ip,
    make_note,
    make_relationship,
    make_report,
    make_url,
    stairwell_identity,
    valid_hash,
)
from connectors_sdk import BaseDataProcessor
from connectors_sdk.exceptions.error import DataRetrievalError

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from connector.state import ConnectorState


def _iso(dt: datetime) -> str:
    """STIX timestamp; converts to UTC so the literal `Z` is correct."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_aware(value: Any) -> datetime | None:
    """Parse an ISO-8601 source timestamp, keeping its offset (naive = UTC)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _bucket(raw: dict[str, Any]) -> str | None:
    mal_eval = raw.get("malEval") or raw.get("mal_eval") or {}
    return mal_eval.get("probabilityBucket") or mal_eval.get("probability_bucket")


@dataclass
class Batch:
    """What one run fetched: the window, its objects, and where it stopped."""

    run_started: datetime
    cutoff: datetime
    window_end: datetime
    cel: str
    entries: list[dict[str, Any]]
    fetched: int
    filtered: int
    # Token of the first unread page when the run stopped at the cap; None
    # when the window was read to its end.
    resume_token: str | None


class MalEvalFilesProcessor(BaseDataProcessor):
    """Imports MalEval-malicious files: a file hash Indicator per file, with the
    IPs, domains, and URLs extracted from it as related observables, wrapped
    in a per-run Grouping or Report.

    `collect()` reads one window (resuming a pending one first) up to
    `import_max_indicators`, checked between pages; `transform()` converts it
    and moves the checkpoints in `ConnectorState`.
    """

    settings: ConnectorSettings
    state: ConnectorState

    work_name = "Stairwell MalEval import"

    def post_init(self) -> None:
        s = self.settings.stairwell
        self.client = StairwellClient(
            api_token=s.api_token.get_secret_value(),
            base_url=str(s.api_base_url),
            organization_id=s.organization_id or None,
            user_id=s.user_id or None,
        )
        self.tlp = s.import_tlp
        self.wrapper = s.import_wrapper
        self.min_bucket = s.import_min_bucket
        self.allowed_buckets = set(normalize_min_bucket(s.import_min_bucket))
        self.max_indicators = max(1, int(s.import_max_indicators))
        self.page_size = max(1, int(s.import_page_size))
        self.first_run_window = parse_iso_duration(s.import_first_run_window)
        self.indicator_validity = timedelta(
            days=max(1, int(s.import_indicator_validity_days))
        )

    # ------------------------------------------------------------------
    # collect: fetch raw pages, no STIX
    # ------------------------------------------------------------------
    def collect(self) -> Batch:
        run_started = datetime.now(tz=timezone.utc)
        state = self.state
        state.migrate_legacy()
        if state.pending_cutoff is not None:
            cutoff = state.pending_cutoff
            window_end = state.pending_window_end or run_started
            page_token = state.pending_page_token
        else:
            cutoff = window_start(state.watermark, self.first_run_window, run_started)
            window_end = run_started
            page_token = None

        cel = build_cel_filter(cutoff=cutoff)
        self.logger.info(
            "Stairwell import window", {"cutoff": _iso(cutoff), "filter": cel}
        )

        entries: list[dict[str, Any]] = []
        fetched = filtered = 0
        resumed = page_token is not None
        page_num = 0
        # The cap is checked between pages, never mid-page: a resume token
        # points at a page boundary, so stopping mid-page would skip the rest
        # of that page. A run may overshoot the cap by less than one page.
        while True:
            page_num += 1
            status, data = self.client.list_objects_metadata(
                cel_filter=cel, page_size=self.page_size, page_token=page_token
            )
            if status >= 400 or not isinstance(data, dict):
                if resumed and page_num == 1 and 400 <= status < 500 and status != 429:
                    # The saved token is no longer accepted: restart the same
                    # window from its first page within this run.
                    self.logger.warning(
                        "Stairwell rejected the saved page token; restarting window",
                        {"status": status},
                    )
                    page_token, resumed, page_num = None, False, 0
                    continue
                raise DataRetrievalError(
                    f"Stairwell list_objects_metadata returned status {status} "
                    f"on page {page_num}; the watermark was not advanced."
                )
            page = (
                data.get("objectMetadatas")
                or data.get("object_metadatas")
                or data.get("objects")
                or []
            )
            if not isinstance(page, list):
                raise DataRetrievalError(
                    f"Stairwell list_objects_metadata page {page_num} has no "
                    "object list; the watermark was not advanced."
                )
            for raw in page:
                if not isinstance(raw, dict):
                    continue
                fetched += 1
                # Client-side bucket filter (server-side `in` returns 500). An
                # object without a bucket has no evidence it meets the minimum.
                if _bucket(raw) not in self.allowed_buckets:
                    filtered += 1
                    continue
                entries.append(raw)

            next_token = data.get("nextPageToken") or data.get("next_page_token")
            if not next_token:
                return Batch(
                    run_started,
                    cutoff,
                    window_end,
                    cel,
                    entries,
                    fetched,
                    filtered,
                    None,
                )
            page_token = next_token
            if len(entries) >= self.max_indicators:
                return Batch(
                    run_started,
                    cutoff,
                    window_end,
                    cel,
                    entries,
                    fetched,
                    filtered,
                    page_token,
                )

    # ------------------------------------------------------------------
    # transform: convert to STIX and move the checkpoints, no network
    # ------------------------------------------------------------------
    def transform(self, batch: Batch) -> list[dict[str, Any]]:
        objects: list[dict[str, Any]] = []
        seen: set[str] = set()
        emitted = 0
        for raw in batch.entries:
            new_objects = self._build_for_object(raw, batch.run_started)
            if not new_objects:
                self.logger.warning(
                    "Skipping Stairwell object with an invalid SHA-256",
                    {"sha256": str(raw.get("sha256"))[:80]},
                )
                continue
            for obj in new_objects:
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    objects.append(obj)
            emitted += 1

        truncated = batch.resume_token is not None
        if truncated:
            self.state.pending_cutoff = batch.cutoff
            self.state.pending_window_end = batch.window_end
            self.state.pending_page_token = batch.resume_token
        else:
            self.state.watermark = batch.window_end
            self.state.pending_cutoff = None
            self.state.pending_window_end = None
            self.state.pending_page_token = None

        self.logger.info(
            "Stairwell import run converted",
            {
                "fetched": batch.fetched,
                "filtered": batch.filtered,
                "indicators": emitted,
                "truncated": truncated,
            },
        )
        if not emitted:
            return []
        return [stairwell_identity(), *objects, *self._wrapper(batch, objects, emitted)]

    def _wrapper(
        self, batch: Batch, objects: list[dict[str, Any]], emitted: int
    ) -> list[dict[str, Any]]:
        """The per-run Grouping/Report (and truncation Note when capped).

        The seed is the run's start time (microsecond precision), so every
        run, including each run that resumes a capped window, gets its own
        wrapper.
        """
        run_label = batch.run_started.strftime("%Y-%m-%d %H:%M UTC")
        run_id = batch.run_started.isoformat()
        seed = f"stairwell-import-run|{run_id}"
        name = f"Stairwell MalEval import — {run_label}"
        truncated = batch.resume_token is not None
        lines = [
            "Stairwell scheduled import run.",
            f"- **Cutoff window:** {_iso(batch.cutoff)} → {_iso(batch.window_end)}",
            f"- **CEL filter:** `{batch.cel}`",
            f"- **Min bucket (client-side):** {self.min_bucket}",
            f"- **Objects fetched:** {batch.fetched}",
            f"- **Filtered by bucket:** {batch.filtered}",
            f"- **Indicators emitted:** {emitted}",
        ]
        if truncated:
            lines.append(
                "- **Truncated:** capped at "
                f"STAIRWELL_IMPORT_MAX_INDICATORS={self.max_indicators}"
            )
        refs = [o["id"] for o in objects]
        if self.wrapper == "report":
            wrapper = make_report(
                seed=seed,
                name=name,
                object_refs=refs,
                published=_iso(batch.run_started),
                description="\n".join(lines),
                tlp=self.tlp,
            )
        else:
            wrapper = make_grouping(
                seed=seed,
                name=name,
                object_refs=refs,
                description="\n".join(lines),
                context="malware-analysis",
                tlp=self.tlp,
            )
        out = [wrapper]
        if truncated:
            out.append(
                make_note(
                    seed=f"stairwell-import-truncation|{run_id}",
                    abstract="Stairwell Import Truncation",
                    content=(
                        "This run reached "
                        f"STAIRWELL_IMPORT_MAX_INDICATORS={self.max_indicators} "
                        f"after {batch.fetched} objects ({emitted} indicators "
                        "emitted). The remaining objects in this window are "
                        "imported by the next run."
                    ),
                    object_refs=[wrapper["id"]],
                    tlp=self.tlp,
                )
            )
        return out

    # ------------------------------------------------------------------
    # Per-object STIX construction
    # ------------------------------------------------------------------
    def _build_for_object(
        self, raw: dict[str, Any], run_started: datetime
    ) -> list[dict[str, Any]]:
        """File SCO, Indicator, and related network observables; [] if invalid.

        The SHA-256 is the only value interpolated into a pattern, so an
        object whose hash is not 64 hex characters is skipped: an invalid
        pattern makes OpenCTI reject the whole bundle.
        """
        sha256 = raw.get("sha256") or raw.get("SHA256")
        if not valid_hash("SHA-256", sha256):
            return []
        sha256 = sha256.lower()
        bucket = _bucket(raw)

        valid_from = (
            _parse_aware(
                raw.get("stairwellFirstSeenTime")
                or raw.get("globalFirstSeenTime")
                or raw.get("uploadTime")
            )
            or run_started
        )
        file_sco = make_file_by_sha256(
            sha256,
            tlp=self.tlp,
            sha1=raw.get("sha1") or raw.get("SHA1"),
            md5=raw.get("md5") or raw.get("MD5"),
        )
        indicator = make_indicator(
            pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
            name=f"Stairwell MalEval file: {sha256[:12]}…",
            seed=f"stairwell-file-indicator|{sha256}",
            valid_from=_iso(valid_from),
            valid_until=_iso(valid_from + self.indicator_validity),
            description=f"MalEval bucket: {bucket}",
            confidence=score_for_bucket(bucket),
            external_references=[
                make_external_reference(
                    "Stairwell",
                    self.client.object_ui_url(sha256),
                    f"Stairwell file detail for {sha256}",
                )
            ],
            tlp=self.tlp,
        )
        out = [
            file_sco,
            indicator,
            make_based_on_relationship(indicator["id"], file_sco["id"], tlp=self.tlp),
        ]

        # Network values extracted from the file are related observables, not
        # Indicators: they include benign infrastructure (OS update hosts,
        # public resolvers, XML namespaces), and an Indicator would put them on
        # blocklists fed from OpenCTI at the file's confidence.
        net = raw.get("networkIndicators") or raw.get("network_indicators") or {}
        if isinstance(net, dict):
            for values, kind in (
                (net.get("ipAddresses") or net.get("ip_addresses") or [], "ip"),
                (net.get("hostnames") or [], "hostname"),
                (net.get("urls") or [], "url"),
            ):
                if not isinstance(values, list):
                    continue
                for value in values:
                    if value and isinstance(value, str):
                        out.extend(
                            self._network_observable(value, kind, file_sco["id"])
                        )
        return out

    def _network_observable(
        self, value: str, kind: str, file_id: str
    ) -> list[dict[str, Any]]:
        if kind == "ip":
            sco = make_ip(value, tlp=self.tlp)
            if sco is None:
                return []
            ui_url = self.client.ip_ui_url(sco["value"])
        elif kind == "hostname":
            sco = make_domain(value, tlp=self.tlp)
            ui_url = self.client.hostname_ui_url(sco["value"])
        elif kind == "url":
            sco = make_url(value, tlp=self.tlp)
            if sco is None:
                return []
            ui_url = self.client.url_ui_url(value)
        else:
            return []
        sco["external_references"] = [
            make_external_reference(
                "Stairwell", ui_url, f"Stairwell intel for {sco['value']}"
            )
        ]
        return [
            sco,
            make_relationship(file_id, sco["id"], "related-to", tlp=self.tlp),
        ]
