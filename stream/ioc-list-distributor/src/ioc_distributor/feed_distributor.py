"""Feed distributor: serves the plain-text IOC lists over HTTP(S), plus the scheduled exporter.

Run: python -m ioc_distributor (service feed-distributor).

Endpoints (optional authentication, FEED_DISTRIBUTOR_AUTH_MODE = none | basic | bearer;
when on, every endpoint needs it except /health):
  GET /feeds/ip.txt | domain.txt | url.txt | hash.txt   (+ hash_<algo>.txt if split)
  GET /feeds/<custom name>_ip.txt ...                    (each enabled custom feed)
      A file of a disabled type or of a disabled / renamed custom feed returns 404
      (the old file stays on disk).
  GET /health   200 when the last export is recent, 503 otherwise
  GET /stats    database counts, stream activity, last export per file
  GET /         list of the endpoints

HTTP and HTTPS can run at the same time, on separate ports.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Awaitable, Callable

import uvicorn
from common import config
from common.storage import open_store
from common.version import __version__
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from ioc_distributor.exporter import FeedExporter
from ioc_distributor.feed_auth import FeedAuth, FeedAuthMiddleware

log = logging.getLogger("feed-distributor")

config.setup_logging()
FD = config.feed_distributor_settings()
EXPORT = config.export_settings()

log.info("IOC List Distributor %s: feed distributor", __version__)
store = open_store()
log.info("IOC store: %s", store.describe())
for warning in FD.warnings:
    log.warning(warning)
AUTH = FeedAuth(FD.auth_mode, FD.auth_user, FD.auth_passtoken)
log.info(
    "Feed authentication: %s",
    FD.auth_mode if AUTH.enabled else "none (open to anyone who can reach the port)",
)
for warning in EXPORT.warnings:
    log.warning(warning)
for note in EXPORT.notes:
    log.info(note)
exporter = FeedExporter(store, EXPORT)  # creates the feeds / backups / tmp folders
SERVED_FILES = exporter.served_files()
stop_event = threading.Event()

app = FastAPI(
    title="OpenCTI IOC List Distributor",
    version=__version__,
    docs_url="/docs" if FD.docs_enabled else None,
    redoc_url=None,
    openapi_url="/openapi.json" if FD.docs_enabled else None,
)


@app.middleware("http")
async def no_cache_for_feeds(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """404 for files no longer served; no-cache headers on the feed files."""
    path = request.url.path
    if path.startswith("/feeds/") and path[len("/feeds/") :] not in SERVED_FILES:
        # Disabled type, disabled / renamed custom feed, or a stray file: not served.
        return PlainTextResponse("Not Found", status_code=404)
    response = await call_next(request)
    if request.url.path.startswith("/feeds/"):
        # Clients may keep a copy but must revalidate (ETag / Last-Modified -> 304).
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/")
def index() -> dict:
    """List of the feed URLs."""
    return {
        "feeds": [f"/feeds/{name}" for name, _, _ in exporter.feeds()],
        "health": "/health",
        "stats": "/stats",
    }


@app.get("/health")
def health() -> JSONResponse:
    """Liveness of the export."""
    age = exporter.seconds_since_success()
    max_age = EXPORT.interval_minutes * 60 * 3
    healthy = age is not None and age <= max_age
    body = {
        "status": "ok" if healthy else "stale",
        "seconds_since_last_export": None if age is None else round(age),
        "max_age_seconds": max_age,
    }
    return JSONResponse(body, status_code=200 if healthy else 503)


@app.get("/stats")
def stats() -> dict:
    """Stream, store and export statistics."""
    meta = store.get_all_meta()
    return {
        "version": __version__,
        "database": {
            "values_by_type": store.counts_by_type(),
            "indicators": store.count_indicators(),
        },
        "stream": {
            "last_event_at": meta.get("stream_last_event_at"),
            "last_event_type": meta.get("stream_last_event_type"),
            "events_processed": int(meta.get("stream_events_total") or 0),
            "indicators_skipped": int(meta.get("stream_indicators_skipped_total") or 0),
        },
        "export": exporter.status(),
        "settings": {
            "interval_minutes": EXPORT.interval_minutes,
            "rolling_window_minutes": EXPORT.rolling_window_minutes,
            "rolling_window_minutes_by_type": {
                t: EXPORT.window_minutes(t) for t in EXPORT.rolling_window_by_type
            },
            "base_attribute": EXPORT.base_attribute,
            "sort_order": EXPORT.sort_order,
            "max_entries": EXPORT.max_entries,
            "hard_max_entries": EXPORT.hard_max_entries or None,
            "warn_drop_percent": EXPORT.warn_drop_percent or None,
            "error_drop_percent": EXPORT.error_drop_percent or None,
            "types_enabled": {t: EXPORT.type_is_enabled(t) for t in config.IOC_TYPES},
            "feeds": [
                {
                    "feed": spec.label,
                    "name": spec.name,
                    "max_entries": {
                        t: spec.max_entries.get(t) or None
                        for t in EXPORT.enabled_types()
                    },
                    "cap_settings": {
                        t: spec.cap_settings.get(t) for t in EXPORT.enabled_types()
                    },
                    "files": [spec.file_name(t, a) for t, a in exporter.groups()],
                }
                for spec in EXPORT.feed_specs()
            ],
            "exclusions": EXPORT.exclude_sources,
            "exclude_expired": EXPORT.exclude_expired,
            "ip_min_prefix": {
                "v4": EXPORT.ip_min_prefix_v4,
                "v6": EXPORT.ip_min_prefix_v6,
            },
            "backup_retention": EXPORT.backup_retention,
            "auth_mode": FD.auth_mode,
        },
    }


# Outermost layer: checks the credentials before any route (including /docs and unknown paths).
app.add_middleware(FeedAuthMiddleware, auth=AUTH, public_paths=("/health",))

# Static serving gives ETag / Last-Modified / 304 and HEAD, and blocks path traversal.
app.mount(
    "/feeds", StaticFiles(directory=config.FEEDS_DIR, check_dir=False), name="feeds"
)


def _servers() -> list[uvicorn.Server]:
    common = {
        "host": FD.host,
        "log_level": config.LOG_LEVEL,
        "server_header": False,
        "proxy_headers": False,
    }
    servers = []
    if FD.http_enabled:
        servers.append(uvicorn.Server(uvicorn.Config(app, port=FD.http_port, **common)))
        log.info("HTTP enabled on %s:%d", FD.host, FD.http_port)
    if FD.https_enabled:
        servers.append(
            uvicorn.Server(
                uvicorn.Config(
                    app,
                    port=FD.https_port,
                    ssl_certfile=FD.tls_cert_file,
                    ssl_keyfile=FD.tls_key_file,
                    **common,
                )
            )
        )
        log.info("HTTPS enabled on %s:%d", FD.host, FD.https_port)
    return servers


async def _serve(servers: list[uvicorn.Server]) -> None:
    tasks = [asyncio.create_task(server.serve()) for server in servers]
    _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for server in servers:  # one listener stopped: stop the other one too
        server.should_exit = True
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


def main() -> None:
    """Entry point of the feed-distributor service."""
    threading.Thread(
        target=exporter.run_forever, args=(stop_event,), name="exporter", daemon=True
    ).start()
    try:
        asyncio.run(_serve(_servers()))
    finally:
        stop_event.set()


if __name__ == "__main__":
    main()
