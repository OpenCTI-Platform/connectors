"""Builds the plain-text IOC lists (one entry per line) from the local IOC store.

Each run:
1. selects the values of each type inside the rolling window (base attribute
   created / modified / first_seen_local / last_updated_local), skipping expired
   indicators, newest first (or highest score first), up to the entry limit;
2. applies the last-line safety filters (non-public IPs, exclude lists); every IP,
   domain and URL left out is logged with the reason (once when it is first left out,
   then in a per-export summary) and listed in /stats;
3. formats the entries kept (e.g. the URL scheme stripped) - formatting is a separate
   step from filtering, so each can be tested on its own;
4. compares the new count with the count saved at the previous export (export_state.json,
   not a re-read of the file) for EXPORT_KEEP_PREVIOUS_ON_EMPTY / EXPORT_MAX_DROP_PERCENT;
5. copies the current file to backups/<stem>_<timestamp><ext> (every run, even when
   the content did not change), the timestamp being when that version was generated;
6. writes the new file atomically (temp file + rename): a reader never sees half a file;
7. keeps the newest BACKUP_RETENTION backups per file and deletes the rest.

Custom feeds: each IOC type is queried ONCE per run and filtered, formatted and
de-duplicated once into a ranked list; the main feed and every custom feed take the first N
entries of that same list (their own cap), so with the same data, settings and run time the
files are byte-identical, and every smaller feed is a subset of every larger one. The
keep-previous check (step 4) runs per group: the files of one type (one hash algorithm with
split files) across all feeds are written together or all keep their previous version.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import threading
from datetime import datetime, timedelta, timezone

from common import config
from common.storage import IocStore
from common.timeutil import iso
from common.url_util import url_host, url_without_scheme

log = logging.getLogger("ioc-exporter")

# <stem>_<timestamp><ext>: ip.txt -> ip_20261028T110307Z.txt (the feed's own extension).
_BACKUP_NAME = re.compile(
    r"^(?P<stem>.+)_(?P<ts>\d{8}T\d{6}Z)(?P<ext>\.[A-Za-z0-9]+)?$"
)
STATE_FILE = "export_state.json"  # per-file entry count of the last published version
DROPPED_LIST_LIMIT = 500  # values left out listed per file in /stats
DROPPED_TYPES = {
    "ip": "IP(s)",
    "domain": "domain(s)",
    "url": "URL(s)",
}  # types that can be left out


_NAMED_RANGES = [
    (ipaddress.ip_network(cidr), label)
    for cidr, label in (
        ("0.0.0.0/8", "'this network' (RFC 1122)"),
        ("10.0.0.0/8", "private (RFC 1918)"),
        ("100.64.0.0/10", "carrier-grade NAT (RFC 6598)"),
        ("127.0.0.0/8", "loopback"),
        ("169.254.0.0/16", "link-local"),
        ("172.16.0.0/12", "private (RFC 1918)"),
        ("192.0.0.0/24", "IETF protocol assignments (RFC 6890)"),
        ("192.0.2.0/24", "documentation TEST-NET-1 (RFC 5737)"),
        ("192.168.0.0/16", "private (RFC 1918)"),
        ("198.18.0.0/15", "benchmarking (RFC 2544)"),
        ("198.51.100.0/24", "documentation TEST-NET-2 (RFC 5737)"),
        ("203.0.113.0/24", "documentation TEST-NET-3 (RFC 5737)"),
        ("224.0.0.0/4", "multicast"),
        ("240.0.0.0/4", "reserved (RFC 1112)"),
        ("::/128", "unspecified"),
        ("::1/128", "loopback"),
        ("fc00::/7", "unique local (RFC 4193)"),
        ("fe80::/10", "link-local"),
        ("ff00::/8", "multicast"),
        ("2001:db8::/32", "documentation (RFC 3849)"),
    )
]


def non_public_reason(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str | None:
    """Why an IP / CIDR is not public, or None when it is public.

    A range that only partly covers a reserved block (e.g. 192.168.0.0/15) is left
    out too: blocking it would also block the private addresses inside it.
    """
    for named, label in _NAMED_RANGES:
        if named.version == net.version and net.subnet_of(named):
            return f"{label}, {named}"
    for named, label in _NAMED_RANGES:
        if named.version == net.version and net.overlaps(named):
            return f"overlaps {label}, {named}"
    if net.is_global and not net.is_multicast:
        return None
    return "reserved / not globally routable"


class FeedExporter:
    """Writes the feed files from the IOC store and keeps the export status for /stats."""

    def __init__(self, store: IocStore, settings: config.ExportSettings) -> None:
        self.store = store
        self.s = settings
        self._lock = threading.Lock()
        self._last_success: datetime | None = None
        self._status = {
            "last_run_at": None,
            "last_success_at": None,
            "last_error": None,
            "files": {},
        }
        self._dropped_before: dict[str, dict[str, str]] = (
            {}
        )  # file -> {value: reason}, last export
        self._capped_before: set[str] = (
            set()
        )  # files cut at the entry limit in the last export
        for directory in (config.FEEDS_DIR, config.BACKUP_DIR, config.TMP_DIR):
            os.makedirs(directory, exist_ok=True)
        self._state_path = os.path.join(config.DATA_DIR, STATE_FILE)
        self._state: dict[str, dict] = self._load_state()

    # ------------------------------------------------------------------ status
    def groups(self) -> list[tuple[str, str | None]]:
        """(ioc type, hash algorithm filter) of each enabled kind of file, in a fixed file order."""
        groups = [(t, None) for t in config.IOC_TYPES if self.s.type_is_enabled(t)]
        if self.s.hash_split_files and self.s.type_is_enabled("hash"):
            groups += [("hash", algo) for algo in self.s.hash_algorithms]
        return groups

    def feed_files(self) -> list[tuple[str, str, str | None, config.FeedSpec]]:
        """(file name, ioc type, hash algorithm filter, feed) of every file served."""
        return [
            (spec.file_name(t, algo), t, algo, spec)
            for spec in self.s.feed_specs()
            for t, algo in self.groups()
        ]

    def feeds(self) -> list[tuple[str, str, str | None]]:
        """(file name, ioc type, hash algorithm filter) of every file served, all feeds."""
        return [(name, t, algo) for name, t, algo, _spec in self.feed_files()]

    def served_files(self) -> frozenset:
        """Names of the files served under /feeds/."""
        return frozenset(name for name, _t, _a in self.feeds())

    def status(self) -> dict:
        """A copy of the last export status (for /stats)."""
        with self._lock:
            return {
                **self._status,
                "files": {k: dict(v) for k, v in self._status["files"].items()},
            }

    def seconds_since_success(self) -> float | None:
        """Seconds since the last successful export, or None before the first one."""
        with self._lock:
            if self._last_success is None:
                return None
            return (datetime.now(timezone.utc) - self._last_success).total_seconds()

    # --------------------------------------------------------------------- run
    def run_forever(self, stop: threading.Event) -> None:
        """Export every EXPORT_INTERVAL_MINUTES until stop is set."""
        log.info(
            "Exporter started: every %d min, window (min) %s on '%s', limit %s, sort by %s",
            self.s.interval_minutes,
            {t: (self.s.window_minutes(t) or "none") for t in config.IOC_TYPES},
            self.s.base_attribute,
            self.s.max_entries,
            self.s.sort_order,
        )
        for line in self.describe_feeds():
            log.info(line)
        while not stop.is_set():
            self.export_once()
            stop.wait(self.s.interval_minutes * 60)

    def describe_feeds(self) -> list[str]:
        """Startup table: each feed, its caps per type, the hard limit and the disabled types."""
        lines = [
            f"Feeds: {1 + len(self.s.custom_feeds)} (main + {len(self.s.custom_feeds)} custom); "
            f"hard limit {self.s.hard_max_entries or 'none'}; types exported: "
            f"{', '.join(self.s.enabled_types()) or 'none'}"
        ]
        for spec in self.s.feed_specs():
            caps = ", ".join(
                f"{t}={spec.max_entries.get(t) or 'no cap'}"
                for t in self.s.enabled_types()
            )
            files = ", ".join(spec.file_name(t, a) for t, a in self.groups())
            lines.append(
                f"  {spec.label:<24} caps: {caps or '-'} | files: {files or '-'}"
            )
        return lines

    def export_once(self) -> None:
        """Run one export; an error is logged and kept in the status, never raised."""
        started = datetime.now(timezone.utc)
        try:
            now = iso(started)
            cutoffs = {}  # per IOC type: window start, or None for no window
            for ioc_type in config.IOC_TYPES:
                minutes = self.s.window_minutes(ioc_type)
                cutoffs[ioc_type] = (
                    iso(started - timedelta(minutes=minutes)) if minutes > 0 else None
                )
            if self.s.db_retention_days > 0:
                purged = self.store.purge_older_than(
                    iso(started - timedelta(days=self.s.db_retention_days))
                )
                if purged:
                    log.info(
                        "Purged %d IOC row(s) older than %d days",
                        purged,
                        self.s.db_retention_days,
                    )

            files = {}
            rows_by_type: dict[str, list] = (
                {}
            )  # one query per IOC type, shared by every feed
            for ioc_type, algo in self.groups():
                if ioc_type not in rows_by_type:
                    rows_by_type[ioc_type] = self._select(
                        ioc_type, now, cutoffs[ioc_type]
                    )
                dropped: dict[str, str] = {}
                ranked = self._rank(ioc_type, algo, rows_by_type[ioc_type], dropped)
                group = []
                for spec in self.s.feed_specs():
                    file_name = spec.file_name(ioc_type, algo)
                    cap: dict = {}
                    entries = self._cut(
                        ranked,
                        spec.max_entries.get(ioc_type, 0),
                        now,
                        cutoffs[ioc_type],
                        cap,
                    )
                    group.append((file_name, spec, entries, cap))
                published = self._publish_group(group, started)
                for file_name, spec, _entries, cap in group:
                    info = published[file_name]
                    info["feed"] = spec.label
                    info["window_minutes"] = self.s.window_minutes(ioc_type)
                    info["cap"] = self._report_cap(file_name, ioc_type, cap, spec)
                    if ioc_type in DROPPED_TYPES:
                        if spec.index == 0:
                            info["dropped"] = self._report_dropped(
                                file_name, dropped, ioc_type
                            )
                        else:  # the same values as the main feed: logged once, under the main file
                            info["dropped"] = {
                                "count": len(dropped),
                                "see": self.s.main_feed().file_name(ioc_type),
                            }
                    files[file_name] = info
            rows_by_type.clear()
            self._prune_backups()

            with self._lock:
                self._last_success = started
                self._status.update(
                    last_run_at=now, last_success_at=now, last_error=None, files=files
                )
            log.info(
                "Export done: %s",
                ", ".join(self._summary(name, info) for name, info in files.items()),
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # Any error: keep serving the last files and try again next interval.
            log.exception("Export failed")
            with self._lock:
                self._status.update(last_run_at=iso(started), last_error=str(exc))

    @staticmethod
    def _summary(name: str, info: dict) -> str:
        """One file in the 'Export done' line: what is served, and why when it is not the new export."""
        capped = info.get("cap", {}).get("capped")
        if info.get("status") == "kept_previous":
            return (
                f"{name}={info['entries']} (kept previous; new export {info.get('new_entries', 0)}"
                + (", capped)" if capped else ")")
            )
        return f"{name}={info['entries']}" + (" (capped)" if capped else "")

    # ----------------------------------------------------------------- content
    def _select(self, ioc_type: str, now: str, cutoff: str | None) -> list:
        """The one database read for a type in a run: every value in the window, ranked."""
        return self.store.select_for_export(
            ioc_type,
            self.s.base_attribute,
            cutoff,
            now if self.s.exclude_expired else None,
            self.s.sort_order,
        )

    def _rank(
        self,
        ioc_type: str,
        algo: str | None,
        rows: list[tuple[str, str]],
        dropped: dict | None = None,
    ) -> list[tuple[str, str]]:
        """Filter -> format -> de-duplicate, in the query's order: [(entry, value)].

        The query's ORDER BY ends with the value itself, so the order is total and the
        same data always gives the same list; every feed is cut from the top of it.
        """
        allowed_algos = {algo} if algo else set(self.s.hash_algorithms)
        ranked: list[tuple[str, str]] = []
        seen: set[str] = set()
        for value, sub_type in rows:
            if ioc_type == "hash" and sub_type not in allowed_algos:
                continue
            reason = self._drop_reason(ioc_type, value)
            if reason:
                if ioc_type in DROPPED_TYPES and dropped is not None:
                    dropped[value] = reason
                continue
            entry = self._format_entry(ioc_type, value)
            if not entry or entry in seen:
                continue
            seen.add(entry)
            ranked.append((entry, value))
        return ranked

    def _cut(
        self,
        ranked: list[tuple[str, str]],
        limit: int,
        now: str,
        cutoff: str | None,
        cap: dict | None = None,
    ) -> list[str]:
        """The first `limit` entries (0 = all), sorted for a stable file."""
        kept = ranked[:limit] if limit else ranked
        if cap is not None:
            cap.update(
                limit=limit,
                available=len(ranked),
                last_kept_value=kept[-1][1] if kept else None,
                first_left_out_value=(
                    ranked[limit][1] if limit and len(ranked) > limit else None
                ),
                cutoff=cutoff,
                expiry_now=now if self.s.exclude_expired else None,
            )
        entries = [entry for entry, _value in kept]
        entries.sort()  # stable output: unchanged sets give identical files
        return entries

    def _report_cap(
        self,
        file_name: str,
        ioc_type: str,
        cap: dict,
        spec: config.FeedSpec | None = None,
    ) -> dict:
        """Log a file cut at the entry limit and return the /stats summary.

        WARNING when a file starts being cut (and at the first export after a restart),
        INFO at every later export while it stays cut, INFO when it is no longer cut.
        """
        limit, available = cap.get("limit", 0), cap.get("available", 0)
        capped = bool(limit) and available > limit
        info = {
            "limit": limit or None,
            "available": available,
            "capped": capped,
            "left_out": max(available - limit, 0) if capped else 0,
        }
        if capped:
            date_of = getattr(
                self.store, "export_date_of", None
            )  # optional store method
            last_kept = (
                date_of(ioc_type, self.s.base_attribute, cap["last_kept_value"])
                if date_of
                else None
            )
            info["sort_order"] = self.s.sort_order
            info[f"last_kept_{self.s.base_attribute}"] = last_kept
            detail = f"last kept {self.s.base_attribute} {last_kept or 'unknown'}"
            if self.s.sort_order == "score":
                # In score order the useful figure is the score at the cut, not a date.
                score_of = getattr(
                    self.store, "export_score_of", None
                )  # optional store method

                def _score(value: str | None) -> int | None:
                    if not score_of or value is None:
                        return None
                    return score_of(
                        ioc_type,
                        self.s.base_attribute,
                        cap.get("cutoff"),
                        cap.get("expiry_now"),
                        value,
                    )

                lowest_kept = _score(cap.get("last_kept_value"))
                highest_out = _score(cap.get("first_left_out_value"))
                info["lowest_kept_score"] = lowest_kept
                info["highest_left_out_score"] = highest_out
                detail = (
                    f"lowest kept score {'unknown' if lowest_kept is None else lowest_kept}, "
                    f"highest left out score {'unknown' if highest_out is None else highest_out}, "
                    + detail
                )
            setting = (
                spec.cap_settings.get(ioc_type)
                if spec and spec.cap_settings
                else f"EXPORT_MAX_ENTRIES_{ioc_type.upper()}"
            )
            msg = "%s capped at %d of %d available, %d left out (%s; sort %s, %s)"
            args = (
                file_name,
                limit,
                available,
                available - limit,
                setting,
                self.s.sort_order,
                detail,
            )
            if file_name in self._capped_before:
                log.info(msg, *args)
            else:
                log.warning(msg, *args)
            self._capped_before.add(file_name)
        elif file_name in self._capped_before:
            log.info(
                "%s no longer capped: %d available, limit %s",
                file_name,
                available,
                limit or "none",
            )
            self._capped_before.discard(file_name)
        return info

    # Filtering: whether a value goes in the feed at all. No formatting here.
    def _drop_reason(self, ioc_type: str, value: str) -> str | None:
        """Why a value is left out of the feed, or None when it is exported."""
        if ioc_type == "ip":
            return self._ip_drop_reason(value)
        if ioc_type == "domain":
            return self._domain_excluded(value)
        if ioc_type == "url":
            host = url_host(value)
            if not host:
                return None
            ip_reason = self._ip_host_excluded(host)
            if ip_reason:
                return ip_reason
            return self._domain_excluded(host)
        return None

    def _ip_drop_reason(self, value: str) -> str | None:
        """Why an IP / CIDR is left out of ip.txt, or None when it is exported."""
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return "invalid IP / CIDR"
        min_prefix = (
            self.s.ip_min_prefix_v4 if net.version == 4 else self.s.ip_min_prefix_v6
        )
        if min_prefix and net.prefixlen < min_prefix:
            # Always applied, even with EXPORT_DROP_NON_PUBLIC_IPS=false: one bad indicator
            # such as 64.0.0.0/3 would otherwise block a large part of the internet.
            return (
                f"too wide: /{net.prefixlen}, minimum /{min_prefix} "
                f"(EXPORT_IP_MIN_PREFIX_V{net.version})"
            )
        if self.s.drop_non_public_ips:
            reason = non_public_reason(net)
            if reason:
                return f"non-public: {reason}"
        for excluded in self.s.ip_exclude:
            if excluded.version == net.version and net.overlaps(excluded):
                return f"exclude list: overlaps {excluded}"
        return None

    # Formatting: how a kept value is written in the file. No filtering here.
    def _format_entry(self, ioc_type: str, value: str) -> str:
        if ioc_type == "url" and self.s.url_strip_scheme:
            return url_without_scheme(value)
        return value

    @staticmethod
    def _render_file(entries: list[str]) -> str:
        """The file body: one entry per line, a final newline, empty file for no entries."""
        return "\n".join(entries) + "\n" if entries else ""

    def _report_dropped(
        self, file_name: str, dropped: dict[str, str], ioc_type: str = "ip"
    ) -> dict:
        """Log the values (IPs, domains, URLs) left out of a file and return the /stats summary.

        Each value is logged at INFO the first time it is left out (after a restart:
        once at the first export), so the log does not repeat every few minutes.
        Every export logs a one-line summary, and at DEBUG every value again.
        """
        before = self._dropped_before.get(file_name, {})
        for value in sorted(dropped):
            if value not in before:
                log.info("%s: not exported: %s (%s)", file_name, value, dropped[value])
            else:
                log.debug("%s: not exported: %s (%s)", file_name, value, dropped[value])
        for value in sorted(set(before) - set(dropped)):
            log.info(
                "%s: no longer left out: %s (removed from the database, now allowed, or out of the window)",
                file_name,
                value,
            )
        self._dropped_before[file_name] = dict(dropped)

        by_reason: dict[str, int] = {}
        for reason in dropped.values():
            key = reason.split(":", 1)[0]
            by_reason[key] = by_reason.get(key, 0) + 1
        if dropped:
            log.info(
                "%s: %d %s left out (%s)",
                file_name,
                len(dropped),
                DROPPED_TYPES[ioc_type],
                ", ".join(f"{k}: {v}" for k, v in sorted(by_reason.items())),
            )
        listed = sorted(dropped.items())[:DROPPED_LIST_LIMIT]
        return {
            "count": len(dropped),
            "by_reason": by_reason,
            "values": [{"value": v, "reason": r} for v, r in listed],
            "values_truncated": len(dropped) > DROPPED_LIST_LIMIT,
        }

    def _ip_host_excluded(self, host: str) -> str | None:
        """A URL whose host is an IP inside EXPORT_IP_EXCLUDE is left out of url.txt."""
        try:
            ip = ipaddress.ip_address(
                host
            )  # url_host() already strips the IPv6 [brackets]
        except ValueError:
            return None  # a name, not an IP: the domain exclude list decides
        for excluded in self.s.ip_exclude:
            if excluded.version == ip.version and ip in excluded:
                return f"exclude list: in {excluded}"
        return None

    def _domain_excluded(self, domain: str) -> str | None:
        """The reason a domain (or a URL's host) is left out: the first exclude list entry it matches."""
        domain = domain.lower()
        for excluded in self.s.domain_exclude:
            if domain == excluded or domain.endswith("." + excluded):
                return f"exclude list: matches {excluded}"
        return None

    # ------------------------------------------------------------------- files
    # Export state: the entry count of each published file, saved after every write, so
    # the drop protection never depends on re-reading (or on edits to) the feed file.
    def _load_state(self) -> dict:
        try:
            with open(self._state_path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log.warning(
                "Could not read %s (%s): the entry counts are read from the feed files once",
                self._state_path,
                exc,
            )
            return {}

    def _save_state(self) -> None:
        tmp_path = os.path.join(config.TMP_DIR, f"{STATE_FILE}.tmp")
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(self._state, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, self._state_path)

    def _previous_count(self, file_name: str, target: str) -> int | None:
        """Entries in the version being replaced; None when there is no previous file."""
        if not os.path.isfile(target):
            return None
        saved = self._state.get(file_name, {}).get("entries")
        if isinstance(saved, int):
            return saved
        # No saved count (state file missing or unreadable): count the lines of the feed file once.
        with open(target, encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())

    def _hold_reason(
        self, file_name: str, target: str, entries: list[str]
    ) -> tuple[str | None, int | None]:
        """(reason to keep the previous file or None, entries in the previous file)."""
        previous = self._previous_count(file_name, target)
        if previous:
            if not entries and self.s.keep_previous_on_empty:
                return "new export was empty", previous
            if (
                self.s.max_drop_percent
                and len(entries) < previous * (100 - self.s.max_drop_percent) / 100
            ):
                return "drop above EXPORT_MAX_DROP_PERCENT", previous
        return None, previous

    def _write(
        self,
        file_name: str,
        target: str,
        entries: list[str],
        started: datetime,
        previous: int | None,
    ) -> dict:
        if previous is not None and self.s.backup_retention > 0:
            self._backup(target, file_name)

        tmp_path = os.path.join(config.TMP_DIR, f"{file_name}.tmp")
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(self._render_file(entries))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, target)
        self._state[file_name] = {"entries": len(entries), "generated_at": iso(started)}
        self._save_state()
        self._alert_drop(file_name, len(entries), previous)
        return {
            "entries": len(entries),
            "status": "written",
            "generated_at": iso(started),
        }

    def _alert_drop(self, file_name: str, new: int, previous: int | None) -> None:
        """EXPORT_WARN/ERROR_DROP_PERCENT: log a large drop of a published file (never holds it).

        One line per file, at the highest level reached. Compared with the previous export only;
        nothing is logged for a feed's first file (no previous count).
        """
        if not previous or new >= previous:
            return
        level = None
        if (
            self.s.error_drop_percent
            and new < previous * (100 - self.s.error_drop_percent) / 100
        ):
            level = logging.ERROR
        elif (
            self.s.warn_drop_percent
            and new < previous * (100 - self.s.warn_drop_percent) / 100
        ):
            level = logging.WARNING
        if level:
            pct = round((previous - new) * 100 / previous)
            log.log(
                level,
                "%s: %d entries vs %d last export (-%d%%), published",
                file_name,
                new,
                previous,
                pct,
            )

    def _warn_hold(
        self, file_name: str, reason: str, entries: list[str], previous: int
    ) -> None:
        if reason == "new export was empty":
            log.warning(
                "%s: new export is empty, keeping the previous %d entries",
                file_name,
                previous,
            )
        else:
            log.warning(
                "%s: new export has %d entries vs %d before (drop > %d%%), keeping the previous file",
                file_name,
                len(entries),
                previous,
                self.s.max_drop_percent,
            )

    def _publish_group(
        self,
        group: list[tuple[str, config.FeedSpec, list[str], dict]],
        started: datetime,
    ) -> dict:
        """Write the files of one type across all feeds together, or keep all their previous files.

        If one file fails the keep-previous check, every file of the group that has a previous
        version keeps it, so the feeds never get out of step. A file with no previous version
        (a feed just added) is written anyway: there is nothing to keep, and a missing file would
        return 404 to the client. A group of one file (no custom feeds) is the plain check.
        """
        checks = {}
        failed = []
        for file_name, _spec, entries, _cap in group:
            target = os.path.join(config.FEEDS_DIR, file_name)
            reason, previous = self._hold_reason(file_name, target, entries)
            checks[file_name] = (target, reason, previous)
            if reason:
                failed.append(file_name)
                self._warn_hold(file_name, reason, entries, previous)
        result = {}
        for file_name, _spec, entries, _cap in group:
            target, reason, previous = checks[file_name]
            if failed and previous is not None:
                if not reason:
                    reason = f"held with {', '.join(failed)} (files of one type are published together)"
                    log.warning("%s: keeping the previous file: %s", file_name, reason)
                result[file_name] = self._kept_previous(
                    file_name, target, previous or 0, len(entries), reason
                )
            else:
                if failed:
                    log.info(
                        "%s: written although %s kept the previous file: no previous version to keep",
                        file_name,
                        ", ".join(failed),
                    )
                result[file_name] = self._write(
                    file_name, target, entries, started, previous
                )
        return result

    def _kept_previous(
        self, file_name: str, target: str, previous: int, new_entries: int, reason: str
    ) -> dict:
        """/stats entry for a file left in place: the date of the file actually served."""
        generated = self._state.get(file_name, {}).get("generated_at")
        if not generated:  # no saved date (state file missing): use the file's own time
            try:
                generated = iso(
                    datetime.fromtimestamp(os.path.getmtime(target), timezone.utc)
                )
            except OSError:
                generated = None
        return {
            "entries": previous,
            "status": "kept_previous",
            "reason": reason,
            "new_entries": new_entries,
            "generated_at": generated,
        }

    @staticmethod
    def backup_name(file_name: str, generated: datetime) -> str:
        """ip.txt -> ip_20261028T110307Z.txt; the feed's own extension is kept."""
        stem, ext = os.path.splitext(file_name)
        return f"{stem}_{generated.strftime('%Y%m%dT%H%M%SZ')}{ext}"

    @classmethod
    def _backup(cls, target: str, file_name: str) -> None:
        generated = datetime.fromtimestamp(os.path.getmtime(target), tz=timezone.utc)
        shutil.copy2(
            target,
            os.path.join(config.BACKUP_DIR, cls.backup_name(file_name, generated)),
        )

    def _prune_backups(self) -> None:
        groups: dict[str, list[tuple[str, str]]] = {}
        for name in os.listdir(config.BACKUP_DIR):
            match = _BACKUP_NAME.match(name)
            if match:
                groups.setdefault(match["stem"] + (match["ext"] or ""), []).append(
                    (match["ts"], name)
                )
        for items in groups.values():
            items.sort(reverse=True)
            for _ts, name in items[self.s.backup_retention :]:
                try:
                    os.remove(os.path.join(config.BACKUP_DIR, name))
                except OSError as exc:
                    log.warning("Could not delete old backup %s: %s", name, exc)
