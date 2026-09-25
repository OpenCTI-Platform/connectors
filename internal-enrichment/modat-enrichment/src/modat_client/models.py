"""Typed model of the Modat Magnify host-details response (``GET /host/{ip}/v1``).

Modat records are large, deeply nested, and partial: any field may be missing,
``null``, or occasionally the wrong primitive type (a number where a string is
expected, a string CVSS like ``"N/A"``, etc.). These models are intentionally
**lenient and total** — parsing a real host record must *never* raise:

- unknown fields are ignored (``extra="ignore"``);
- ``null``/wrong-typed containers normalise to empty values;
- malformed list entries are dropped;
- unparseable scalars coerce to ``None`` (or the field default) rather than
  raising a ``ValidationError``.

This replaces scattered ``dict.get("a", {}).get("b")`` chains in the connector,
converter, and summary builder with typed attribute access, without making
parsing more fragile than the raw-dict access it replaced. Genuinely
polymorphic leaf blobs (distinguished names, SAN extensions, fingerprint
entries, HTTP headers) are kept as plain dicts/``Any`` and parsed by the
existing ``ModatUtils`` helpers, which already tolerate arbitrary shapes.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _ModatModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


# --- lenient ``mode="before"`` coercers: never raise; unparseable -> None/empty ---


def _as_str(value: Any) -> Any:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return None  # dicts/lists are not scalar strings


def _as_float(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _as_int(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text)
        except ValueError:
            try:
                return int(float(text))
            except ValueError:
                return None
    return None


def _as_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in ("", "false", "0", "no", "n", "off")
    return bool(value)


def _as_bool_or_none(value: Any) -> Any:
    return None if value is None else _as_bool(value)


def _dict_or_none(value: Any) -> Any:
    return value if isinstance(value, dict) else None


def _dict_or_empty(value: Any) -> Any:
    return value if isinstance(value, dict) else {}


def _list_or_empty(value: Any) -> Any:
    return value if isinstance(value, list) else []


def _keep_dicts(value: Any) -> Any:
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _keep_strings(value: Any) -> Any:
    return (
        [item for item in value if isinstance(item, str) and item]
        if isinstance(value, list)
        else []
    )


class Asn(_ModatModel):
    number: int | None = None
    org: str | None = None

    _number = field_validator("number", mode="before")(_as_int)
    _org = field_validator("org", mode="before")(_as_str)


class Geo(_ModatModel):
    country_name: str | None = None
    city_name: str | None = None
    country_iso_code: str | None = None

    _strs = field_validator(
        "country_name", "city_name", "country_iso_code", mode="before"
    )(_as_str)


class Cve(_ModatModel):
    id: str | None = None
    cvss: float | None = None
    is_kev: bool = False

    _id = field_validator("id", mode="before")(_as_str)
    _cvss = field_validator("cvss", mode="before")(_as_float)
    _is_kev = field_validator("is_kev", mode="before")(_as_bool)


class Tls(_ModatModel):
    fingerprint_sha256: str | None = None
    fingerprint_sha1: str | None = None
    serial_number: str | None = None
    issuer: dict[str, Any] | None = None
    subject: dict[str, Any] | None = None
    valid_from: str | None = None
    expires_at: str | None = None
    is_self_signed: bool | None = None
    supported_versions: list[Any] = Field(default_factory=list)
    extensions: dict[str, Any] = Field(default_factory=dict)
    raw: str | None = None

    _strs = field_validator(
        "fingerprint_sha256",
        "fingerprint_sha1",
        "serial_number",
        "valid_from",
        "expires_at",
        "raw",
        mode="before",
    )(_as_str)
    _dns = field_validator("issuer", "subject", mode="before")(_dict_or_none)
    _self_signed = field_validator("is_self_signed", mode="before")(_as_bool_or_none)
    _versions = field_validator("supported_versions", mode="before")(_list_or_empty)
    _extensions = field_validator("extensions", mode="before")(_dict_or_empty)


class Fingerprints(_ModatModel):
    service: Any = None
    os: Any = None
    technologies: list[Any] = Field(default_factory=list)

    _technologies = field_validator("technologies", mode="before")(_list_or_empty)


class Ssh(_ModatModel):
    hassh: str | None = None
    server_id: str | None = None

    _strs = field_validator("hassh", "server_id", mode="before")(_as_str)


class Http(_ModatModel):
    title: str | None = None
    status_code: int | None = None
    headers: dict[str, Any] = Field(default_factory=dict)

    _title = field_validator("title", mode="before")(_as_str)
    _status = field_validator("status_code", mode="before")(_as_int)
    _headers = field_validator("headers", mode="before")(_dict_or_empty)


class Service(_ModatModel):
    transport: str | None = None
    protocol: str | None = None
    last_scanned_port: int | None = None
    ports: list[Any] = Field(default_factory=list)
    scanned_at: str | None = None
    banner: str | None = None
    fingerprints: Fingerprints = Field(default_factory=Fingerprints)
    ssh: Ssh | None = None
    http: Http | None = None
    tls: Tls | None = None
    cves: list[Cve] = Field(default_factory=list)

    _strs = field_validator(
        "transport", "protocol", "scanned_at", "banner", mode="before"
    )(_as_str)
    _port = field_validator("last_scanned_port", mode="before")(_as_int)
    _ports = field_validator("ports", mode="before")(_list_or_empty)
    _fingerprints = field_validator("fingerprints", mode="before")(_dict_or_empty)
    _nested = field_validator("ssh", "http", "tls", mode="before")(_dict_or_none)
    _cves = field_validator("cves", mode="before")(_keep_dicts)


class ModatHost(_ModatModel):
    asn: Asn = Field(default_factory=Asn)
    geo: Geo = Field(default_factory=Geo)
    fqdns: list[str] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    cves: list[Cve] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    is_anycast: bool = False

    _asn_geo = field_validator("asn", "geo", mode="before")(_dict_or_empty)
    _fqdns_tags = field_validator("fqdns", "tags", mode="before")(_keep_strings)
    _services_cves = field_validator("services", "cves", mode="before")(_keep_dicts)
    _is_anycast = field_validator("is_anycast", mode="before")(_as_bool)
