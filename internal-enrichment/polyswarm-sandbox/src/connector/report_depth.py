"""
Report depth: dropped files and extracted malware configuration.

Turns parts of a PolySwarm sandbox report that the connector already downloads
into STIX objects:

* dropped files become File observables related to the detonated observable;
* the command and control (C2) addresses in an extracted malware
  configuration become observables, and optionally Indicators.

Report shapes this module reads (measured on real tasks, read only):

* CAPE: ``report.dropped[]`` with ``sha256``, ``md5``, ``sha1``, ``size``,
  ``type`` (a file(1) description, not a MIME type), ``name`` (list) and
  ``guest_paths``. The CAPE reports measured have no extracted-configuration
  field, so CAPE contributes dropped files only.
* Triage: ``report.dumped[]`` with ``sha256``, ``md5``, ``sha1``, ``size``,
  ``path`` and ``kind``; and ``report.extracted[].config`` with ``family``,
  ``rule`` and, for some families, ``c2`` (strings such as ``host:port``,
  ``host`` or ``ip:port``).
* Both: ``sandbox_artifacts[]`` entries of type ``dropped_file`` are named by
  SHA-256 and may carry a ``mimetype``.
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

import stix2

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_MIME_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$"
)
_URL_SCHEMES = ("http", "https", "ftp")

# Malware -> drops -> File is not emitted by default because it is not known
# to be accepted by every OpenCTI version; related-to always is.
MALWARE_DROPS_FILE = False

_INTERNAL_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".localdomain",
    ".home.arpa",
    ".corp",
    ".intranet",
    ".home",
)

# Shared or legitimate services that malware uses as dead drops. Observables
# are still created for them, but never an Indicator: blocking the whole
# service on one sample's configuration would be wrong. Subdomains match.
SHARED_SERVICE_DOMAINS = (
    "telegram.org",
    "t.me",
    "discord.com",
    "discordapp.com",
    "discord.gg",
    "pastebin.com",
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "dropbox.com",
    "onedrive.live.com",
    "1drv.ms",
    "sharepoint.com",
    "transfer.sh",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
)

# Subdomains of these identify one customer's tunnel, so only the apex is
# treated as a shared service.
TUNNEL_SERVICE_DOMAINS = ("ngrok.io", "ngrok-free.app", "ngrok.app")

C2_INDICATOR_VALID_DAYS = 30
MAX_C2_PER_REPORT = 20


# ---------------------------------------------------------------------------
# Extraction (raw sandbox task -> small plain dicts)
# ---------------------------------------------------------------------------


def extract_report_depth(raw: dict | None) -> dict[str, Any]:
    """Pull dropped files and configured C2 addresses out of a raw sandbox task.

    Never raises on odd input: anything unexpected is skipped.
    """
    empty: dict[str, Any] = {"dropped_files": [], "c2": []}
    if not isinstance(raw, dict):
        return empty
    report = raw.get("report")
    if not isinstance(report, dict):
        return empty
    return {
        "dropped_files": _extract_dropped_files(raw, report),
        "c2": _extract_config_c2(report, raw),
    }


def _mime_by_sha256(raw: dict) -> dict[str, str]:
    """MIME types of ``dropped_file`` artifacts, keyed by lower-case SHA-256."""
    out: dict[str, str] = {}
    for art in raw.get("sandbox_artifacts") or []:
        if not isinstance(art, dict) or art.get("type") != "dropped_file":
            continue
        name = str(art.get("name") or "").lower()
        mime = str(art.get("mimetype") or "").strip().lower()
        if _SHA256_RE.match(name) and _MIME_RE.match(mime):
            out[name] = mime
    return out


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.rstrip("\\/"))[-1]


def _entry_name(entry: dict) -> str | None:
    name = entry.get("name")
    if isinstance(name, list):
        name = next((n for n in name if isinstance(n, str) and n.strip()), None)
    if isinstance(name, str) and name.strip():
        # Triage uses internal resource names such as files/0x0001-4.dat.
        if not name.startswith("files/"):
            return _basename(name.strip())[:255] or None
    paths = entry.get("guest_paths")
    if isinstance(paths, str):
        paths = [paths]
    for p in paths or []:
        if isinstance(p, str) and p.strip():
            return _basename(p.strip())[:255] or None
    path = entry.get("path")
    if isinstance(path, str) and path.strip():
        return _basename(path.strip())[:255] or None
    return None


def _extract_dropped_files(raw: dict, report: dict) -> list[dict[str, Any]]:
    own = str(raw.get("sha256") or "").lower()
    mimes = _mime_by_sha256(raw)
    entries: list = []
    for key in ("dropped", "dumped"):
        value = report.get(key)
        if isinstance(value, list):
            entries.extend(value)

    seen: set[str] = set()
    files: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        sha256 = str(entry.get("sha256") or "").strip().lower()
        if not _SHA256_RE.match(sha256) or sha256 == own or sha256 in seen:
            continue
        seen.add(sha256)
        item: dict[str, Any] = {"sha256": sha256}
        for algo, rx in (("md5", _MD5_RE), ("sha1", _SHA1_RE)):
            val = str(entry.get(algo) or "").strip().lower()
            if rx.match(val):
                item[algo] = val
        size = entry.get("size")
        if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
            item["size"] = size
        name = _entry_name(entry)
        if name:
            item["name"] = name
        if sha256 in mimes:
            item["mime_type"] = mimes[sha256]
        files.append(item)
    return files


def _public_host(host: str) -> bool:
    """True for a public IP address or a plausible public domain name.

    Private, loopback, link-local, reserved and unspecified addresses, and
    internal names (no dot, or a local-only suffix) are rejected.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if not _DOMAIN_RE.match(host):
            return False
        return not host.endswith(_INTERNAL_SUFFIXES)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def _is_shared_service(sco_type: str, value: str) -> bool:
    """True when the C2 is just the bare address of a shared or legitimate service.

    Domains: the listed domain and its subdomains, except tunnel services,
    where only the apex counts (a subdomain there is one customer's tunnel).
    Urls: only a bare host (empty or "/" path, no query or fragment). A URL
    with a specific path, such as a webhook or a stored object, is specific
    enough to keep its Indicator.
    """
    if sco_type == "url":
        parts = urlsplit(value)
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            return False
        host = (parts.hostname or "").lower().strip(".")
    elif sco_type == "domain-name":
        host = value.lower()
    else:
        return False
    for d in SHARED_SERVICE_DOMAINS:
        if host == d:
            return True
        if host.endswith("." + d) and d not in TUNNEL_SERVICE_DOMAINS:
            return True
    return False


def _classify_c2(value: str) -> dict[str, Any] | None:
    """Turn one configured C2 string into ``{type, value, port?}`` or None."""
    text = value.strip()
    if not text or len(text) > 2048:
        return None
    if "://" in text:
        try:
            parts = urlsplit(text)
            url_host = parts.hostname
        except ValueError:
            return None
        if parts.scheme.lower() not in _URL_SCHEMES or not url_host:
            return None
        if not _public_host(url_host.lower().strip(".")):
            return None
        return {"type": "url", "value": text}

    host, port = text, None
    if text.startswith("["):  # [v6]:port
        end = text.find("]")
        if end == -1:
            return None
        host = text[1:end]
        rest = text[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
        elif rest:
            return None
    elif text.count(":") == 1:
        h, _, p = text.partition(":")
        if not p.isdigit():
            return None
        host, port = h, int(p)
    host = host.strip().strip(".").lower()
    if port is not None and not 0 < port < 65536:
        return None

    if not _public_host(host):
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        out = {"type": "domain-name", "value": host}
    else:
        out = {"type": "ipv4-addr" if ip.version == 4 else "ipv6-addr"}
        out["value"] = str(ip)
    if port is not None:
        out["port"] = port
    return out


def _extract_config_c2(report: dict, raw: dict) -> list[dict[str, Any]]:
    provider = str(raw.get("sandbox") or "").lower() or None
    extracted = report.get("extracted")
    if not isinstance(extracted, list):
        return []
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for ext in extracted:
        cfg = ext.get("config") if isinstance(ext, dict) else None
        if not isinstance(cfg, dict):
            continue
        c2_list = cfg.get("c2")
        if isinstance(c2_list, str):
            c2_list = [c2_list]
        if not isinstance(c2_list, list):
            continue
        family = cfg.get("family") or cfg.get("rule")
        for c2 in c2_list:
            if not isinstance(c2, str):
                continue
            item = _classify_c2(c2)
            if not item or (item["type"], item["value"]) in seen:
                continue
            seen.add((item["type"], item["value"]))
            if isinstance(family, str) and family.strip():
                item["family"] = family.strip()[:100]
            if provider:
                item["provider"] = provider
            found.append(item)
            if len(found) >= MAX_C2_PER_REPORT:
                return found
    return found


def select_pcap_artifact(raw: dict | None) -> dict | None:
    """The first ``pcap`` sandbox artifact of a task, or None."""
    if not isinstance(raw, dict):
        return None
    for art in raw.get("sandbox_artifacts") or []:
        if (
            isinstance(art, dict)
            and art.get("type") == "pcap"
            and art.get("instance_id")
        ):
            return art
    return None


# ---------------------------------------------------------------------------
# STIX construction
# ---------------------------------------------------------------------------


def _sco_id(sco_type: str, value: str) -> str:
    # Same scheme the connector already uses for its network observables.
    return f"{sco_type}--{uuid.uuid5(uuid.NAMESPACE_URL, value)}"


def entity_marking_refs(entity: dict) -> list[str]:
    """Marking definition ids carried by the detonated observable."""
    refs: list[str] = []
    for ref in entity.get("object_marking_refs") or []:
        if isinstance(ref, str):
            refs.append(ref)
    for marking in entity.get("objectMarking") or []:
        if isinstance(marking, dict):
            ref = marking.get("standard_id")
            if isinstance(ref, str) and ref.startswith("marking-definition--"):
                refs.append(ref)
    return list(dict.fromkeys(refs))


def build_report_depth_objects(
    builder: Any,
    entity: dict,
    malware_id: str | None,
    depths: list[dict[str, Any]],
    *,
    max_dropped_files: int,
    create_observables: bool,
    c2_indicators: bool,
    create_indicators: bool,
) -> list[dict]:
    """Objects for dropped files and configured C2, carrying the entity's markings."""
    objects = _build_objects(
        builder,
        entity,
        malware_id,
        depths,
        max_dropped_files=max_dropped_files,
        create_observables=create_observables,
        c2_indicators=c2_indicators,
        create_indicators=create_indicators,
    )
    refs = entity_marking_refs(entity)
    if refs:
        for obj in objects:
            obj["object_marking_refs"] = list(refs)
    return objects


def _build_objects(
    builder: Any,
    entity: dict,
    malware_id: str | None,
    depths: list[dict[str, Any]],
    *,
    max_dropped_files: int,
    create_observables: bool,
    c2_indicators: bool,
    create_indicators: bool,
) -> list[dict]:
    """STIX objects for the dropped files and configured C2 of all providers.

    ``builder`` is the StixBuilder (author id, timestamp and relationship
    factory). Everything is deduplicated across providers.
    """
    if not create_observables:
        return []
    objects: list[dict] = []
    entity_id = entity["id"]
    own_sha = str(builder._get_sha256(entity) or "").lower()

    # --- dropped files -----------------------------------------------------
    if max_dropped_files > 0:
        seen: set[str] = set()
        for depth in depths:
            # The cap applies to each provider's report; files already
            # created from another provider do not count against it.
            taken = 0
            for item in depth.get("dropped_files", []):
                sha256 = item["sha256"]
                if sha256 == own_sha or sha256 in seen:
                    continue
                if taken >= max_dropped_files:
                    break
                taken += 1
                seen.add(sha256)
                hashes = {"SHA-256": sha256}
                if "md5" in item:
                    hashes["MD5"] = item["md5"]
                if "sha1" in item:
                    hashes["SHA-1"] = item["sha1"]
                props: dict[str, Any] = {"hashes": hashes}
                for key in ("name", "size", "mime_type"):
                    if key in item:
                        props[key] = item[key]
                # stix2 derives the standard deterministic File identifier.
                sco = json.loads(
                    stix2.File(
                        **props,
                        allow_custom=True,
                        x_opencti_created_by_ref=builder.author_id,
                        x_opencti_description=(
                            "File dropped during sandbox analysis. "
                            + builder.OBSERVABLE_DESCRIPTION
                        ),
                    ).serialize()
                )
                fid = sco["id"]
                objects.append(sco)
                objects.append(
                    builder._create_rel(
                        entity_id,
                        "related-to",
                        fid,
                        "File dropped during sandbox analysis",
                    )
                )
                if MALWARE_DROPS_FILE and malware_id:
                    objects.append(builder._create_rel(malware_id, "drops", fid))

    # --- configured C2 -----------------------------------------------------
    seen_c2: set[tuple[str, str]] = set()
    for depth in depths:
        for c2 in depth.get("c2", []):
            key = (c2["type"], c2["value"])
            if key in seen_c2:
                continue
            seen_c2.add(key)
            objects.extend(
                _c2_objects(
                    builder,
                    entity_id,
                    malware_id,
                    c2,
                    with_indicator=c2_indicators and create_indicators,
                )
            )
    return objects


def _c2_objects(
    builder: Any,
    entity_id: str,
    malware_id: str | None,
    c2: dict[str, Any],
    *,
    with_indicator: bool,
) -> list[dict]:
    from pycti import Indicator

    sco_type, value = c2["type"], c2["value"]
    origin = "the malware configuration extracted by the PolySwarm sandbox"
    if c2.get("provider"):
        origin += f" ({c2['provider']})"
    if c2.get("family"):
        origin += f", family {c2['family']}"
    port = f" Port {c2['port']}." if c2.get("port") else ""

    oid = _sco_id(sco_type, value)
    objects: list[dict] = [
        {
            "type": sco_type,
            "spec_version": "2.1",
            "id": oid,
            "value": value,
            "x_opencti_created_by_ref": builder.author_id,
            "x_opencti_description": f"Command and control address from {origin}.{port}",
        },
        builder._create_rel(
            entity_id, "related-to", oid, f"Command and control address from {origin}"
        ),
    ]
    # Malware communicates-with host is accepted for IPs and domains; a Url
    # target is left to the related-to above.
    if malware_id and sco_type != "url":
        objects.append(builder._create_rel(malware_id, "communicates-with", oid))

    if with_indicator and not _is_shared_service(sco_type, value):
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        pattern = f"[{sco_type}:value = '{escaped}']"
        iid = Indicator.generate_id(pattern)
        now = datetime.fromisoformat(builder._now.replace("Z", "+00:00"))
        until = (now + timedelta(days=C2_INDICATOR_VALID_DAYS)).astimezone(timezone.utc)
        main_type = {
            "ipv4-addr": "IPv4-Addr",
            "ipv6-addr": "IPv6-Addr",
            "domain-name": "Domain-Name",
            "url": "Url",
        }[sco_type]
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": iid,
                "created": builder._now,
                "modified": builder._now,
                "created_by_ref": builder.author_id,
                "name": value,
                "description": f"Command and control address from {origin}.{port}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": builder._now,
                "valid_until": until.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "labels": ["c2"],
                "x_opencti_main_observable_type": main_type,
            }
        )
        objects.append(
            builder._create_rel(
                iid, "based-on", oid, "Indicator built from the configured C2 address"
            )
        )
        if malware_id:
            objects.append(builder._create_rel(iid, "indicates", malware_id))
    return objects
