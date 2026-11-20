"""Settings for the OpenCTI IOC List Distributor.

Read from environment variables (docker-compose.yml lists every setting with its default). Without
Docker, the same settings can be put in src/config.yml (see config.yml.sample): an environment
variable always wins over config.yml.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from typing import Callable

from pydantic import ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# config.yml (optional, for running without Docker)
# ---------------------------------------------------------------------------
CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.yml"
)


def _config_items(node: dict, prefix: str = ""):
    """(SETTING_NAME, value) of every leaf: sections and keys joined with '_', upper-cased.

    opencti: {url: ...} -> OPENCTI_URL, custom_feed1: {name: ...} -> CUSTOM_FEED1_NAME.
    """
    for key, value in node.items():
        name = f"{prefix}{str(key).strip().replace('-', '_').upper()}"
        if isinstance(value, dict):
            yield from _config_items(value, f"{name}_")
        else:
            yield name, value


def _config_text(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return str(value)


def load_config_file(path: str = CONFIG_FILE) -> int:
    """Fill the settings missing from the environment from config.yml; returns how many.

    An environment variable always wins (as in the other OpenCTI connectors), and an empty
    value in the file means the default. No file: nothing changes.
    """
    if not os.path.isfile(path):
        return 0
    import yaml  # pylint: disable=import-outside-toplevel

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise SystemExit(f"Cannot read {path}: {exc}") from None
    if not isinstance(data, dict):
        raise SystemExit(
            f"{path}: expected sections of settings (opencti:, connector:, ...)"
        )
    count = 0
    for name, value in _config_items(data):
        if value is None or name in os.environ:
            continue
        os.environ[name] = _config_text(value)
        count += 1
    return count


CONFIG_FILE_SETTINGS = load_config_file()

# ---------------------------------------------------------------------------
# Paths (one shared Docker volume mounted on /data)
# ---------------------------------------------------------------------------
DATA_DIR = os.getenv("DATA_DIR", "/data")
FEEDS_DIR = os.path.join(DATA_DIR, "feeds")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
TMP_DIR = os.path.join(DATA_DIR, "tmp")

IOC_TYPES = ("ip", "domain", "url", "hash")
HASH_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
BASE_ATTRIBUTES = ("created", "modified", "first_seen_local", "last_updated_local")
BASE_ATTRIBUTE_ALIASES = {"created_at": "created", "updated_at": "modified"}
SORT_ORDERS = ("base_attribute", "score")

# Custom feeds: extra sets of files cut from the same export as the main feed.
CUSTOM_FEED_DEFAULT_COUNT = 3
CUSTOM_FEED_MAX_COUNT = 10
DEFAULT_HARD_MAX_ENTRIES = 500000
RESERVED_FEED_NAMES = frozenset(IOC_TYPES)
FEED_NAME_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")

# Feed authentication (FEED_DISTRIBUTOR_AUTH_*): checked here, applied by
# ioc_distributor.feed_auth.
AUTH_MODES = ("none", "basic", "bearer")
# RFC 6750 b64token: what a client can send after "Bearer " without quoting.
BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9\-._~+/]+=*$")
MIN_PASSTOKEN_LENGTH = 16


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _str(name: str, default: str | None = None, required: bool = False) -> str | None:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        if required:
            raise SystemExit(f"Missing required setting: {name}")
        return default
    return value.strip()


def _bool(name: str, default: bool) -> bool:
    value = _str(name)
    if value is None:
        return default
    if value.lower() in ("1", "true", "yes", "on"):
        return True
    if value.lower() in ("0", "false", "no", "off"):
        return False
    raise SystemExit(f"{name} must be true or false, got {value!r}")


def _int(name: str, default: int, minimum: int = 0) -> int:
    value = _str(name)
    if value is None:
        return default
    try:
        number = int(value)
    except ValueError:
        raise SystemExit(f"{name} must be a whole number, got {value!r}") from None
    if number < minimum:
        raise SystemExit(f"{name} must be >= {minimum}, got {number}")
    return number


# Lenient readers for some optional settings: an unreadable value falls back to the default
# and a WARNING is logged at startup (the other settings stop startup on a bad value).
def _soft_bool(name: str, default: bool, warnings: list) -> bool:
    value = _str(name)
    if value is None:
        return default
    if value.lower() in _TRUE:
        return True
    if value.lower() in _FALSE:
        return False
    warnings.append(
        f"{name}={value!r} is not true or false: using the default ({str(default).lower()})"
    )
    return default


def _soft_int(
    name: str,
    default: int | None,
    warnings: list,
    minimum: int = 0,
    maximum: int | None = None,
    default_text: str | None = None,
) -> int | None:
    value = _str(name)
    if value is None:
        return default
    shown = default_text or str(default)
    try:
        number = int(value)
    except ValueError:
        warnings.append(
            f"{name}={value!r} is not a whole number: using the default ({shown})"
        )
        return default
    if number < minimum or (maximum is not None and number > maximum):
        bounds = f"{minimum}-{maximum}" if maximum is not None else f">= {minimum}"
        warnings.append(
            f"{name}={number} is outside {bounds}: using the default ({shown})"
        )
        return default
    return number


def _list(name: str, default: str = "") -> list[str]:
    value = _str(name, default) or ""
    return [item.strip() for item in value.split(",") if item.strip()]


def _exclude_entries(name: str) -> tuple[list[tuple[str, str]], int, str | None]:
    """Entries of one exclude list from the setting NAME (comma-separated) and NAME_FILE (one per line).

    Returns ([(entry, where)], count from the setting, file path or None); `where` names the setting
    or the file and line, for error messages. Blank lines and # comments in the file are skipped.
    The file is read once, at startup: a missing or unreadable file stops startup, because a
    silently empty exclude list would let critical IPs or domains be blocked.
    """
    entries = [(item, name) for item in _list(name)]
    from_env = len(entries)
    path = _str(f"{name}_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError as exc:
            raise SystemExit(
                f"{name}_FILE: cannot read {path!r} ({exc.strerror or exc}); "
                f"fix the path or the volume mount, or leave {name}_FILE empty"
            ) from None
        for number, line in enumerate(lines, 1):
            item = line.split("#", 1)[0].strip()
            if item:
                entries.append((item, f"{name}_FILE {path} line {number}"))
    return entries, from_env, path


def _domain_exclude_entry(item: str, where: str, warnings: list) -> str:
    """Normalise one domain exclude list entry; WARN about entries that match too much or nothing.

    The entry is still used as written (lower-cased, outer dots removed): the warning is there so
    a mistake is seen at startup. A leading '*.' is accepted and means the domain itself, which
    already covers its subdomains.
    """
    entry = item.lower().strip().strip(".")
    if entry.startswith("*."):
        entry = entry[2:].strip(".")
    if not entry:
        return entry
    shown = f"{where}: domain exclude list entry {item!r}"
    try:
        if not re.fullmatch(
            r"[0-9./]+", entry
        ):  # '8.8' or '10.1' is a partial IP, not a domain
            ipaddress.ip_network(entry, strict=False)
        warnings.append(
            f"{shown} looks like an IP or CIDR: the domain exclude list compares text, so "
            "ranges never match and a partial IP matches other IPs; "
            "put IPs and CIDRs in EXPORT_IP_EXCLUDE"
        )
        return entry
    except ValueError:
        pass
    bad = sorted({c for c in entry if c in "*/:@ \t?#"})
    if bad:
        warnings.append(
            f"{shown} contains {' '.join(repr(c) for c in bad)}: it matches nothing; "
            "write a plain domain such as supplier.com (it covers its subdomains)"
        )
    elif "." not in entry:
        warnings.append(
            f"{shown} has no dot: it excludes every domain ending in .{entry}"
        )
    return entry


def _exclude_note(
    label: str, count: int, from_env: int, from_file: int, path: str | None
) -> str:
    """Startup line: unique entries in use, and how many were read from each source."""
    sources = [f"{from_env} from the setting"] + (
        [f"{from_file} from {path}"] if path else []
    )
    return f"{label}: {count} unique entries ({', '.join(sources)})"


LOG_LEVEL = (_str("LOG_LEVEL", "info") or "info").lower()


def setup_logging() -> None:
    """Basic logging until a component sets up its own (pycti does for the connector)."""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


# ---------------------------------------------------------------------------
# Connector (OpenCTI live stream -> IOC store)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ConnectorSettings:
    """Settings of the connector service (OpenCTI connection and live stream)."""

    opencti_url: str
    opencti_token: str
    opencti_ssl_verify: bool
    connector_id: str
    connector_name: str
    live_stream_id: str
    name_fallback: bool
    warnings: tuple = ()  # logged by the connector at startup

    def helper_config(self) -> dict:
        """Configuration handed to pycti's OpenCTIConnectorHelper."""
        return {
            "opencti": {
                "url": self.opencti_url,
                "token": self.opencti_token,
                "ssl_verify": self.opencti_ssl_verify,
            },
            "connector": {
                "id": self.connector_id,
                "type": "STREAM",
                "name": self.connector_name,
                "scope": "indicator",
                "log_level": LOG_LEVEL,
                "live_stream_id": self.live_stream_id,
                # Needed so deletions (and indicators leaving the stream filters) reach us.
                "live_stream_listen_delete": True,
                # Only the indicators themselves, not their related objects.
                "live_stream_no_dependencies": True,
            },
        }


# OpenCTI's built-in streams: every object of the platform, with none of the stream's filters.
GLOBAL_STREAM_IDS = ("live", "raw")


def check_live_stream_id(stream_id: str) -> list[str]:
    """Check CONNECTOR_LIVE_STREAM_ID; returns the startup warnings.

    A ChangeMe placeholder left in the configuration stops startup. The built-in global streams are
    accepted but warned about: they bypass the stream filters (allowlist labels), so every
    indicator of the platform would reach the feeds.
    """
    name = "CONNECTOR_LIVE_STREAM_ID"
    if "changeme" in stream_id.lower():
        raise SystemExit(
            f"{name} is still the placeholder {stream_id!r}: set it to the ID of the "
            "live stream created in OpenCTI (Data > Data sharing > Live streams)"
        )
    if stream_id.lower() in GLOBAL_STREAM_IDS:
        return [
            f"{name}={stream_id!r} is OpenCTI's global stream: it has no filters, so every "
            "indicator of the platform is exported. Use the ID of a filtered live stream"
        ]
    return []


class ConnectorEnvSettings(BaseSettings):
    """The connector service's settings, read from the environment by pydantic-settings.

    Same variable names as before (OPENCTI_URL, CONNECTOR_ID, ...); config.yml is copied into the
    environment first by load_config_file(), so an environment variable still wins over the file.
    An empty value means the default (or "missing" for a required setting).
    """

    model_config = SettingsConfigDict(
        case_sensitive=False,
        env_ignore_empty=True,
        extra="ignore",
        str_strip_whitespace=True,
    )

    opencti_url: str
    opencti_token: str
    opencti_ssl_verify: bool = True
    connector_id: str
    connector_name: str = "IOC List Distributor"
    connector_live_stream_id: str
    parser_name_fallback: bool = False


_CONNECTOR_REQUIRED = (
    "opencti_url",
    "opencti_token",
    "connector_id",
    "connector_live_stream_id",
)


def _settings_error(exc: ValidationError) -> SystemExit:
    """The first problem of a ValidationError, as the startup message the other settings use."""
    error = exc.errors()[0]
    name = str(error["loc"][0]).upper() if error.get("loc") else "settings"
    if error["type"] == "missing":
        return SystemExit(f"Missing required setting: {name}")
    if error["type"].startswith("bool"):
        return SystemExit(f"{name} must be true or false, got {error.get('input')!r}")
    return SystemExit(f"{name}: {error['msg']}")


def connector_settings() -> ConnectorSettings:
    """Read the connector settings (the OpenCTI connection and the live stream)."""
    try:
        env = ConnectorEnvSettings()
    except ValidationError as exc:
        raise _settings_error(exc) from None
    for field in _CONNECTOR_REQUIRED:
        if not getattr(env, field):  # set, but only spaces
            raise SystemExit(f"Missing required setting: {field.upper()}")
    warnings = check_live_stream_id(env.connector_live_stream_id)
    return ConnectorSettings(
        opencti_url=env.opencti_url.rstrip("/"),
        opencti_token=env.opencti_token,
        opencti_ssl_verify=env.opencti_ssl_verify,
        connector_id=env.connector_id,
        connector_name=env.connector_name or "IOC List Distributor",
        live_stream_id=env.connector_live_stream_id,
        name_fallback=env.parser_name_fallback,
        warnings=tuple(warnings),
    )


def apply_proxy_settings() -> bool:
    """Route the connector's outbound HTTP(S) traffic through a proxy if configured.

    pycti talks to OpenCTI with `requests`, which honours these variables.
    Returns True when a proxy is configured.
    """
    proxy = _str("OUTBOUND_PROXY_URL")
    if proxy:
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            os.environ[var] = proxy
    no_proxy = _str("OUTBOUND_NO_PROXY")
    if no_proxy:
        os.environ["NO_PROXY"] = no_proxy
        os.environ["no_proxy"] = no_proxy
    ca_bundle = _str("OUTBOUND_PROXY_CA_BUNDLE")
    if ca_bundle:
        if not os.path.isfile(ca_bundle):
            raise SystemExit(f"OUTBOUND_PROXY_CA_BUNDLE not found: {ca_bundle}")
        os.environ["REQUESTS_CA_BUNDLE"] = ca_bundle
        os.environ["SSL_CERT_FILE"] = ca_bundle
    return bool(proxy or os.getenv("HTTPS_PROXY") or os.getenv("https_proxy"))


# ---------------------------------------------------------------------------
# Export (IOC store -> list files)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FeedSpec:
    """One feed: the main feed (index 0, no prefix) or a custom feed (<name>_<type>.txt)."""

    name: str
    prefix: str
    max_entries: dict  # ioc type -> cap after the hard limit (0 = no cap)
    cap_settings: dict  # ioc type -> the setting that sets the cap (named in the log)
    index: int = 0  # 0 = main feed, n = CUSTOM_FEEDn

    @property
    def label(self) -> str:
        """Name of the feed in the log: 'main' or 'custom: <name>'."""
        return "main" if not self.index else f"custom: {self.name}"

    def file_name(self, ioc_type: str, algo: str | None = None) -> str:
        """File name of one type (or one hash algorithm) in this feed."""
        return (
            f"{self.prefix}hash_{algo}.txt" if algo else f"{self.prefix}{ioc_type}.txt"
        )


@dataclass(frozen=True)
class ExportSettings:
    """Settings of the scheduled export (IOC store -> feed files)."""

    interval_minutes: int
    max_entries: dict  # ioc type -> limit (0 = unlimited)
    rolling_window_minutes: int  # default for every type, 0 = no window
    base_attribute: str
    sort_order: str
    exclude_expired: bool
    hash_algorithms: tuple
    hash_split_files: bool
    url_strip_scheme: bool
    drop_non_public_ips: bool
    ip_exclude: tuple
    domain_exclude: tuple
    keep_previous_on_empty: bool
    max_drop_percent: int
    backup_retention: int
    db_retention_days: int
    rolling_window_by_type: dict = None  # ioc type -> minutes (0 = no window)
    # Widest CIDR exported (0 = no limit): a /3 would block an eighth of the internet.
    ip_min_prefix_v4: int = 24
    ip_min_prefix_v6: int = 48
    # Type switches, hard limit and custom feeds
    type_enabled: dict = None  # ioc type -> exported (default true)
    hard_max_entries: int = 0  # every file of every feed (0 = none)
    custom_feeds: tuple = ()  # FeedSpec of each enabled custom feed
    warnings: tuple = ()  # logged at startup
    notes: tuple = ()  # logged at startup (INFO)
    main_cap_settings: dict = None  # ioc type -> setting behind the main cap
    warn_drop_percent: int = 0  # log a WARNING on a larger drop (file still published)
    error_drop_percent: int = 0  # log an ERROR on a larger drop (file still published)
    exclude_sources: dict = (
        None  # "ip" / "domain" -> entries, from_env, file (for /stats)
    )

    def type_is_enabled(self, ioc_type: str) -> bool:
        """Whether files of this IOC type are exported (EXPORT_ENABLED_<TYPE>)."""
        return self.type_enabled is None or self.type_enabled.get(ioc_type, True)

    def enabled_types(self) -> tuple:
        """The exported IOC types, in IOC_TYPES order."""
        return tuple(t for t in IOC_TYPES if self.type_is_enabled(t))

    def main_feed(self) -> FeedSpec:
        """The FeedSpec of the main feed (no file name prefix)."""
        labels = self.main_cap_settings or {
            t: f"EXPORT_MAX_ENTRIES_{t.upper()}" for t in IOC_TYPES
        }
        return FeedSpec("main", "", self.max_entries, labels, 0)

    def feed_specs(self) -> tuple:
        """The main feed first, then every enabled custom feed in block order."""
        return (self.main_feed(),) + tuple(self.custom_feeds)

    def window_minutes(self, ioc_type: str) -> int:
        """Rolling window for one IOC type: its own setting, else the default."""
        if self.rolling_window_by_type and ioc_type in self.rolling_window_by_type:
            return self.rolling_window_by_type[ioc_type]
        return self.rolling_window_minutes


def export_settings() -> ExportSettings:
    """Read and check the export settings."""
    base = (_str("EXPORT_BASE_ATTRIBUTE", "modified") or "modified").lower()
    base = BASE_ATTRIBUTE_ALIASES.get(base, base)
    if base not in BASE_ATTRIBUTES:
        raise SystemExit(
            f"EXPORT_BASE_ATTRIBUTE must be one of {', '.join(BASE_ATTRIBUTES)}, got {base!r}"
        )

    sort_order = (
        _str("EXPORT_SORT_ORDER", "base_attribute") or "base_attribute"
    ).lower()
    if sort_order not in SORT_ORDERS:
        raise SystemExit(
            f"EXPORT_SORT_ORDER must be one of {', '.join(SORT_ORDERS)}, got {sort_order!r}"
        )

    warnings: list[str] = []
    notes: list[str] = []

    type_enabled = {
        t: _soft_bool(f"EXPORT_ENABLED_{t.upper()}", True, warnings) for t in IOC_TYPES
    }
    for t in IOC_TYPES:
        if not type_enabled[t]:
            notes.append(
                f"EXPORT_ENABLED_{t.upper()}=false: the {t} files of every feed are not exported "
                f"and return 404 (the {t} IOCs are still stored in the database)"
            )
    if not any(type_enabled.values()):
        warnings.append(
            "Every IOC type is disabled (EXPORT_ENABLED_*=false): no feed file is exported or served"
        )

    hard = _soft_int("EXPORT_HARD_MAX_ENTRIES", DEFAULT_HARD_MAX_ENTRIES, warnings)
    if hard == 0:
        warnings.append(
            "EXPORT_HARD_MAX_ENTRIES=0: no hard limit is active; a feed cap of 0 exports "
            "everything in the rolling window"
        )

    def _apply_hard(
        ioc_type: str, cap: int, source: str, setting: str
    ) -> tuple[int, str]:
        """A cap above the hard limit (or 0 = no cap) is reduced to it, with a WARNING."""
        if hard and (cap == 0 or cap > hard):
            if type_enabled[ioc_type]:
                warnings.append(
                    f"{source} [{ioc_type}]: {cap if cap else '0 (no cap)'} reduced to the hard "
                    f"limit EXPORT_HARD_MAX_ENTRIES={hard}"
                )
            return hard, "EXPORT_HARD_MAX_ENTRIES"
        return cap, setting

    default_max = _int("EXPORT_MAX_ENTRIES", 5000)
    max_entries, main_labels = {}, {}
    for t in IOC_TYPES:
        own = _str(f"EXPORT_MAX_ENTRIES_{t.upper()}")
        cap = _int(f"EXPORT_MAX_ENTRIES_{t.upper()}", default_max)
        source = (
            f"EXPORT_MAX_ENTRIES_{t.upper()}"
            if own is not None
            else "EXPORT_MAX_ENTRIES"
        )
        max_entries[t], main_labels[t] = _apply_hard(
            t, cap, source, f"EXPORT_MAX_ENTRIES_{t.upper()}"
        )
    custom_feeds = _custom_feeds(max_entries, type_enabled, _apply_hard, warnings)

    algorithms = []
    for algo in _list("EXPORT_HASH_ALGORITHMS", "md5,sha1,sha256"):
        algo = algo.lower().replace("-", "").replace("_", "")
        if algo not in HASH_ALGORITHMS:
            raise SystemExit(f"EXPORT_HASH_ALGORITHMS: unsupported algorithm {algo!r}")
        algorithms.append(algo)

    # Exclude lists: the setting's value and the optional file are merged, duplicates removed.
    ip_entries, ip_from_env, ip_file = _exclude_entries("EXPORT_IP_EXCLUDE")
    ip_exclude = []
    for cidr, where in ip_entries:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise SystemExit(f"{where}: invalid IP or CIDR {cidr!r}") from None
        if net not in ip_exclude:
            ip_exclude.append(net)
    domain_entries, domain_from_env, domain_file = _exclude_entries(
        "EXPORT_DOMAIN_EXCLUDE"
    )
    domain_exclude = []
    for item, where in domain_entries:
        item = _domain_exclude_entry(item, where, warnings)
        if item and item not in domain_exclude:
            domain_exclude.append(item)
    exclude_sources = {
        "ip": {"entries": len(ip_exclude), "from_env": ip_from_env, "file": ip_file},
        "domain": {
            "entries": len(domain_exclude),
            "from_env": domain_from_env,
            "file": domain_file,
        },
    }
    if ip_file or domain_file:
        notes.append(
            _exclude_note(
                "IP exclude list",
                len(ip_exclude),
                ip_from_env,
                len(ip_entries) - ip_from_env,
                ip_file,
            )
        )
        notes.append(
            _exclude_note(
                "Domain exclude list",
                len(domain_exclude),
                domain_from_env,
                len(domain_entries) - domain_from_env,
                domain_file,
            )
        )

    default_window = _int("EXPORT_ROLLING_WINDOW_MINUTES", 43200)
    # Per-type windows (blank = the default above), e.g. hashes for longer than IPs.
    window_by_type = {
        t: _int(f"EXPORT_ROLLING_WINDOW_MINUTES_{t.upper()}", default_window)
        for t in IOC_TYPES
    }

    min_prefix_v4 = _int("EXPORT_IP_MIN_PREFIX_V4", 24)
    if min_prefix_v4 > 32:
        raise SystemExit(
            f"EXPORT_IP_MIN_PREFIX_V4 must be between 0 and 32, got {min_prefix_v4}"
        )
    min_prefix_v6 = _int("EXPORT_IP_MIN_PREFIX_V6", 48)
    if min_prefix_v6 > 128:
        raise SystemExit(
            f"EXPORT_IP_MIN_PREFIX_V6 must be between 0 and 128, got {min_prefix_v6}"
        )

    max_drop = _int("EXPORT_MAX_DROP_PERCENT", 0)
    if max_drop > 100:
        raise SystemExit("EXPORT_MAX_DROP_PERCENT must be between 0 and 100")

    # Drop alerts: log only, the new file is always published. 0 = off.
    warn_drop = _soft_int("EXPORT_WARN_DROP_PERCENT", 0, warnings, 0, 100)
    error_drop = _soft_int("EXPORT_ERROR_DROP_PERCENT", 0, warnings, 0, 100)
    if warn_drop and error_drop and error_drop <= warn_drop:
        warnings.append(
            f"EXPORT_ERROR_DROP_PERCENT={error_drop} is not above EXPORT_WARN_DROP_PERCENT="
            f"{warn_drop}: every drop above {error_drop}% is logged as an ERROR"
        )

    return ExportSettings(
        interval_minutes=_int("EXPORT_INTERVAL_MINUTES", 5, minimum=1),
        max_entries=max_entries,
        rolling_window_minutes=default_window,
        rolling_window_by_type=window_by_type,
        base_attribute=base,
        sort_order=sort_order,
        exclude_expired=_bool("EXPORT_EXCLUDE_EXPIRED", True),
        hash_algorithms=tuple(algorithms),
        hash_split_files=_bool("EXPORT_HASH_SPLIT_FILES", False),
        url_strip_scheme=_bool("EXPORT_URL_STRIP_SCHEME", True),
        drop_non_public_ips=_bool("EXPORT_DROP_NON_PUBLIC_IPS", True),
        ip_exclude=tuple(ip_exclude),
        domain_exclude=tuple(domain_exclude),
        exclude_sources=exclude_sources,
        keep_previous_on_empty=_bool("EXPORT_KEEP_PREVIOUS_ON_EMPTY", True),
        max_drop_percent=max_drop,
        backup_retention=_int("BACKUP_RETENTION", 5),
        db_retention_days=_int("DB_RETENTION_DAYS", 0),
        ip_min_prefix_v4=min_prefix_v4,
        ip_min_prefix_v6=min_prefix_v6,
        type_enabled=type_enabled,
        hard_max_entries=hard,
        main_cap_settings=main_labels,
        warn_drop_percent=warn_drop,
        error_drop_percent=error_drop,
        custom_feeds=custom_feeds,
        warnings=tuple(warnings),
        notes=tuple(notes),
    )


def _custom_feeds(
    main_caps: dict,
    type_enabled: dict,  # pylint: disable=unused-argument
    apply_hard: Callable[[str, int, str, str], tuple[int, str]],
    warnings: list,
) -> tuple:
    """Read the CUSTOM_FEEDn_* blocks; return the FeedSpec of each enabled one.

    A cap left blank is the main feed cap for that type; CUSTOM_FEEDn_MAX_ENTRIES_<TYPE> beats
    CUSTOM_FEEDn_MAX_ENTRIES. A custom cap may be above the main cap; only the hard limit applies.
    A bad name stops the feed distributor (it would change or clash with the clients' URLs).
    """
    count = _soft_int(
        "CUSTOM_FEED_COUNT",
        CUSTOM_FEED_DEFAULT_COUNT,
        warnings,
        0,
        CUSTOM_FEED_MAX_COUNT,
    )
    for key in sorted(os.environ):
        match = re.match(r"^CUSTOM_FEED(\d+)_ENABLED$", key)
        if match and int(match[1]) > count and (_str(key) or "").lower() in _TRUE:
            warnings.append(
                f"{key}=true is ignored: CUSTOM_FEED_COUNT={count} (raise it to read block {match[1]})"
            )

    specs, names = [], {}
    for n in range(1, count + 1):
        p = f"CUSTOM_FEED{n}_"
        if not _soft_bool(f"{p}ENABLED", False, warnings):
            continue
        name = (_str(f"{p}NAME", f"custom{n}") or f"custom{n}").lower()
        if not FEED_NAME_RE.match(name):
            raise SystemExit(
                f"{p}NAME={name!r}: use 1-64 letters, digits, - and _ only"
            )
        if name in RESERVED_FEED_NAMES:
            raise SystemExit(
                f"{p}NAME={name!r} is reserved ({', '.join(sorted(RESERVED_FEED_NAMES))})"
            )
        if name in names:
            raise SystemExit(
                f"{p}NAME={name!r} is already used by CUSTOM_FEED{names[name]}_NAME"
            )
        names[name] = n
        blank = "blank = the main feed cap"
        base = _soft_int(f"{p}MAX_ENTRIES", None, warnings, default_text=blank)
        caps, labels = {}, {}
        for t in IOC_TYPES:
            own = _soft_int(
                f"{p}MAX_ENTRIES_{t.upper()}", None, warnings, default_text=blank
            )
            if own is not None:
                caps[t], labels[t] = apply_hard(
                    t, own, f"{p}MAX_ENTRIES_{t.upper()}", f"{p}MAX_ENTRIES_{t.upper()}"
                )
            elif base is not None:
                caps[t], labels[t] = apply_hard(
                    t, base, f"{p}MAX_ENTRIES", f"{p}MAX_ENTRIES"
                )
            else:  # the main feed cap, already within the hard limit
                caps[t], labels[t] = (
                    main_caps[t],
                    f"{p}MAX_ENTRIES (blank: main feed cap)",
                )
        specs.append(FeedSpec(name, f"{name}_", caps, labels, n))

    # Every file name must be unique across all feeds (split hash files included).
    seen: dict[str, str] = {}
    main = FeedSpec("main", "", main_caps, {}, 0)
    for spec in [main] + specs:
        for t in IOC_TYPES:
            for algo in [None] + (list(HASH_ALGORITHMS) if t == "hash" else []):
                file_name = spec.file_name(t, algo)
                if file_name in seen and seen[file_name] != spec.label:
                    raise SystemExit(
                        f"Feed file name clash: {file_name} ({seen[file_name]} and {spec.label})"
                    )
                seen[file_name] = spec.label
    return tuple(specs)


# ---------------------------------------------------------------------------
# Feed distributor (the web server the clients download the files from)
# ---------------------------------------------------------------------------
FD_PREFIX = "FEED_DISTRIBUTOR_"


@dataclass(frozen=True)
class FeedDistributorSettings:
    """Settings of the HTTP(S) server that serves the feed files."""

    host: str
    http_enabled: bool
    http_port: int
    https_enabled: bool
    https_port: int
    tls_cert_file: str | None
    tls_key_file: str | None
    docs_enabled: bool
    auth_mode: str = "none"  # none | basic | bearer
    auth_user: str | None = None  # basic only
    auth_passtoken: str | None = None
    warnings: tuple = ()  # logged by the feed distributor at startup


def _auth_settings(
    p: str, http_enabled: bool
) -> tuple[str, str | None, str | None, list[str]]:
    """Read and check FEED_DISTRIBUTOR_AUTH_MODE / _USER / _PASSTOKEN."""
    mode = (_str(f"{p}AUTH_MODE", "none") or "none").lower()
    if mode not in AUTH_MODES:
        raise SystemExit(
            f"{p}AUTH_MODE must be one of {', '.join(AUTH_MODES)}, got {mode!r}"
        )
    user = _str(f"{p}AUTH_USER")
    passtoken = _str(f"{p}AUTH_PASSTOKEN")
    warnings: list[str] = []

    if mode == "none":
        if user or passtoken:
            warnings.append(
                f"{p}AUTH_USER / {p}AUTH_PASSTOKEN are set but ignored: {p}AUTH_MODE=none"
            )
        return mode, None, None, warnings

    if not passtoken:
        raise SystemExit(f"{p}AUTH_MODE={mode} needs {p}AUTH_PASSTOKEN")
    if mode == "basic":
        if not user:
            raise SystemExit(f"{p}AUTH_MODE=basic needs {p}AUTH_USER")
        if ":" in user:
            raise SystemExit(
                f"{p}AUTH_USER cannot contain ':' (Basic authentication separates user and passtoken with it)"
            )
    else:  # bearer
        if not BEARER_TOKEN_RE.match(passtoken):
            raise SystemExit(
                f"{p}AUTH_PASSTOKEN contains characters a Bearer token cannot carry; "
                "use letters, digits and - . _ ~ + / (python -m ioc_distributor.feed_auth make-token)"
            )
        if user:
            warnings.append(
                f"{p}AUTH_USER is ignored with {p}AUTH_MODE=bearer (only the passtoken is used)"
            )
    if len(passtoken) < MIN_PASSTOKEN_LENGTH:
        warnings.append(
            f"{p}AUTH_PASSTOKEN is shorter than {MIN_PASSTOKEN_LENGTH} characters; "
            "use a long random value (python -m ioc_distributor.feed_auth make-token)"
        )
    if http_enabled:
        warnings.append(
            f"Authentication ({mode}) is on while plain HTTP is enabled: the credentials cross "
            f"the network unencrypted on the HTTP port. Prefer HTTPS only ({p}HTTP_ENABLED=false)"
        )
    return mode, user, passtoken, warnings


def feed_distributor_settings() -> FeedDistributorSettings:
    """Read and check the feed distributor settings."""
    p = FD_PREFIX
    http_enabled = _bool(f"{p}HTTP_ENABLED", True)
    auth_mode, auth_user, auth_passtoken, warnings = _auth_settings(p, http_enabled)
    settings = FeedDistributorSettings(
        host=_str(f"{p}HOST", "0.0.0.0"),
        http_enabled=http_enabled,
        http_port=_int(f"{p}HTTP_PORT", 8080, minimum=1),
        https_enabled=_bool(f"{p}HTTPS_ENABLED", False),
        https_port=_int(f"{p}HTTPS_PORT", 8443, minimum=1),
        tls_cert_file=_str(f"{p}TLS_CERT_FILE"),
        tls_key_file=_str(f"{p}TLS_KEY_FILE"),
        docs_enabled=_bool(f"{p}DOCS_ENABLED", False),
        auth_mode=auth_mode,
        auth_user=auth_user,
        auth_passtoken=auth_passtoken,
        warnings=tuple(warnings),
    )
    if not settings.http_enabled and not settings.https_enabled:
        raise SystemExit(f"Enable at least one of {p}HTTP_ENABLED / {p}HTTPS_ENABLED")
    if (
        settings.http_enabled
        and settings.https_enabled
        and settings.http_port == settings.https_port
    ):
        raise SystemExit(f"{p}HTTP_PORT and {p}HTTPS_PORT must differ")
    if settings.https_enabled:
        for name, path in (
            (f"{p}TLS_CERT_FILE", settings.tls_cert_file),
            (f"{p}TLS_KEY_FILE", settings.tls_key_file),
        ):
            if not path or not os.path.isfile(path):
                raise SystemExit(
                    f"HTTPS is enabled but {name} is missing or unreadable: {path!r}"
                )
            try:
                with open(path, "rb") as handle:
                    handle.read(1)
            except OSError as exc:
                raise SystemExit(
                    f"HTTPS is enabled but {name} can't be read by the container user "
                    f"(uid {os.getuid()}): {path!r} ({exc.strerror})"
                ) from exc
    return settings
