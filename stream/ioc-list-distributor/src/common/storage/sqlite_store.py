"""SQLite storage.

A single file on the shared /data volume. The connector writes, the feed distributor
reads; WAL mode lets both work at the same time.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from common.timeutil import utcnow_iso

from .base import IocStore

SCHEMA = """
CREATE TABLE IF NOT EXISTS ioc (
    indicator_id        TEXT NOT NULL,  -- OpenCTI internal id (stable across pattern edits)
    stix_id             TEXT,           -- STIX standard id, for traceability
    ioc_type            TEXT NOT NULL,  -- ip | domain | url | hash
    sub_type            TEXT,           -- ipv4 / ipv6 / domain / url / md5 / sha1 / sha256 / sha512
    value               TEXT NOT NULL,
    name                TEXT,
    score               INTEGER,
    valid_until         TEXT,
    created             TEXT,           -- STIX created (OpenCTI)
    modified            TEXT,           -- STIX modified (OpenCTI)
    first_seen_local    TEXT NOT NULL,  -- first time this connector stored the value
    last_updated_local  TEXT NOT NULL,  -- last create/update event received for it
    PRIMARY KEY (indicator_id, ioc_type, value)
);
CREATE INDEX IF NOT EXISTS idx_ioc_type_created  ON ioc (ioc_type, created);
CREATE INDEX IF NOT EXISTS idx_ioc_type_modified ON ioc (ioc_type, modified);
CREATE INDEX IF NOT EXISTS idx_ioc_type_value    ON ioc (ioc_type, value);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def connect(path: str) -> sqlite3.Connection:
    """Open the database file (WAL mode) and create the schema."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(
        path, timeout=30, check_same_thread=False, isolation_level=None
    )
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE ... COMMIT, or ROLLBACK on any error."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


class SqliteIocStore(IocStore):
    """IocStore in one SQLite file on the data volume."""

    backend_name = "sqlite"

    def __init__(self, path: str) -> None:
        self.path = path
        self.conn = connect(path)
        self.lock = threading.Lock()

    def describe(self) -> str:
        return f"sqlite ({self.path})"

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    # ------------------------------------------------------------------ writes
    def upsert_indicator(
        self,
        indicator_id: str,
        stix_id: str | None,
        iocs: list[tuple[str, str, str]],
        *,
        name: str | None,
        score: int | None,
        valid_until: str | None,
        created: str | None,
        modified: str | None,
    ) -> tuple[int, int, int]:
        now = utcnow_iso()
        wanted = {}
        for ioc_type, sub_type, value in iocs:
            wanted[(ioc_type, value)] = sub_type
        with self.lock, transaction(self.conn) as c:
            existing = {
                (row[0], row[1])
                for row in c.execute(
                    "SELECT ioc_type, value FROM ioc WHERE indicator_id = ?",
                    (indicator_id,),
                )
            }
            stale = existing - set(wanted)
            for ioc_type, value in stale:
                c.execute(
                    "DELETE FROM ioc WHERE indicator_id = ? AND ioc_type = ? AND value = ?",
                    (indicator_id, ioc_type, value),
                )
            for (ioc_type, value), sub_type in wanted.items():
                c.execute(
                    """
                    INSERT INTO ioc (indicator_id, stix_id, ioc_type, sub_type, value, name, score,
                                     valid_until, created, modified, first_seen_local, last_updated_local)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (indicator_id, ioc_type, value) DO UPDATE SET
                        stix_id = excluded.stix_id,
                        sub_type = excluded.sub_type,
                        name = excluded.name,
                        score = excluded.score,
                        valid_until = excluded.valid_until,
                        created = excluded.created,
                        modified = CASE
                            WHEN excluded.modified IS NULL THEN ioc.modified
                            WHEN ioc.modified IS NOT NULL AND excluded.modified < ioc.modified THEN ioc.modified
                            ELSE excluded.modified
                        END,  -- never move modified backwards (out-of-order stream events)
                        last_updated_local = excluded.last_updated_local
                    """,
                    (
                        indicator_id,
                        stix_id,
                        ioc_type,
                        sub_type,
                        value,
                        name,
                        score,
                        valid_until,
                        created,
                        modified,
                        now,
                        now,
                    ),
                )
        added = len(set(wanted) - existing)
        updated = len(set(wanted) & existing)
        return added, updated, len(stale)

    def delete_indicator(self, indicator_id: str, stix_id: str | None = None) -> int:
        with self.lock, transaction(self.conn) as c:
            cursor = c.execute(
                "DELETE FROM ioc WHERE indicator_id = ? OR (? IS NOT NULL AND stix_id = ?)",
                (indicator_id, stix_id, stix_id),
            )
            return cursor.rowcount

    def purge_older_than(self, cutoff_iso: str) -> int:
        with self.lock, transaction(self.conn) as c:
            cursor = c.execute(
                "DELETE FROM ioc WHERE COALESCE(modified, last_updated_local) < ?",
                (cutoff_iso,),
            )
            return cursor.rowcount

    def record_event(self, event_type: str, skipped: bool) -> None:
        now = utcnow_iso()
        upsert = "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value"
        increment = (
            "INSERT INTO meta (key, value) VALUES (?, '1') "
            "ON CONFLICT (key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)"
        )
        with self.lock, transaction(self.conn) as c:
            c.execute(upsert, ("stream_last_event_at", now))
            c.execute(upsert, ("stream_last_event_type", event_type))
            c.execute(increment, ("stream_events_total",))
            if skipped:
                c.execute(increment, ("stream_indicators_skipped_total",))

    # ------------------------------------------------------------------- reads
    def select_for_export(
        self,
        ioc_type: str,
        base_attribute: str,
        cutoff: str | None,
        expiry_now: str | None,
        sort_order: str,
    ) -> list[tuple[str, str]]:
        column = self.check_base_attribute(base_attribute)
        where = ["ioc_type = ?"]
        params: list = [ioc_type]
        if cutoff:
            where.append(f"{column} >= ?")
            params.append(cutoff)
        if expiry_now:
            where.append("(valid_until IS NULL OR valid_until > ?)")
            params.append(expiry_now)
        # value as the last key: a fixed order when dates tie, so the same entries are kept at a cap.
        order = (
            "best_score DESC, ts DESC, value"
            if sort_order == "score"
            else "ts DESC, value"
        )
        sql = (
            f"SELECT value, MAX(sub_type) AS sub, MAX(COALESCE(score, 0)) AS best_score, MAX({column}) AS ts "
            f"FROM ioc WHERE {' AND '.join(where)} GROUP BY value ORDER BY {order}"
        )
        with self.lock:
            return [
                (row[0], row[1]) for row in self.conn.execute(sql, params).fetchall()
            ]

    def export_date_of(
        self, ioc_type: str, base_attribute: str, value: str | None
    ) -> str | None:
        if value is None:
            return None
        column = self.check_base_attribute(base_attribute)
        with self.lock:
            row = self.conn.execute(
                f"SELECT MAX({column}) FROM ioc WHERE ioc_type = ? AND value = ?",
                (ioc_type, value),
            ).fetchone()
        return row[0] if row else None

    def export_score_of(
        self,
        ioc_type: str,
        base_attribute: str,
        cutoff: str | None,
        expiry_now: str | None,
        value: str | None,
    ) -> int | None:
        if value is None:
            return None
        column = self.check_base_attribute(base_attribute)
        where = ["ioc_type = ?", "value = ?"]
        params: list = [ioc_type, value]
        if cutoff:
            where.append(f"{column} >= ?")
            params.append(cutoff)
        if expiry_now:
            where.append("(valid_until IS NULL OR valid_until > ?)")
            params.append(expiry_now)
        with self.lock:
            row = self.conn.execute(
                f"SELECT MAX(COALESCE(score, 0)) FROM ioc WHERE {' AND '.join(where)}",
                params,
            ).fetchone()
        return row[0] if row else None

    def counts_by_type(self) -> dict:
        with self.lock:
            rows = self.conn.execute(
                "SELECT ioc_type, COUNT(DISTINCT value) FROM ioc GROUP BY ioc_type"
            ).fetchall()
        return {row[0]: row[1] for row in rows}

    def count_indicators(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(DISTINCT indicator_id) FROM ioc"
            ).fetchone()[0]

    def get_all_meta(self) -> dict:
        with self.lock:
            return dict(self.conn.execute("SELECT key, value FROM meta").fetchall())
