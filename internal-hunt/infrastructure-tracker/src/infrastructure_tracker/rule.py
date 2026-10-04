"""Fingerprint rules of infrastructure hunts and their per-source queries.

A hunt for the ``internet`` platform carries a native query in the ``internet``
language: a YAML (or JSON) document listing infrastructure fingerprints::

    fingerprints:
      - kind: jarm
        value: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
      - kind: certificate_subject
        value: CN=Major Cobalt Strike, OU=AdvancedPenTesting, O=cobaltstrike
    sources: [censys, silentpush]       # optional, default: every configured source
    queries:                            # optional, raw queries in the source language
      urlscan: 'page.title:"Login" AND page.asn:AS20473'

Each source receives one query matching any of the fingerprints it can
search, plus its raw query.
"""

import json
from collections.abc import Callable, Iterable
from typing import Any, Literal

import yaml
from connectors_sdk.connectors.internal_hunt import HuntTranslationError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

FingerprintKind = Literal[
    "jarm",
    "ja4x",
    "ja4s",
    "certificate_sha256",
    "certificate_subject",
    "certificate_issuer",
    "http_title",
    "http_body_sha256",
    "http_server",
    "banner_sha256",
    "asn",
]
SourceName = Literal["censys", "silentpush", "urlscan", "cymru_scout"]

SOURCES: tuple[str, ...] = ("censys", "silentpush", "urlscan", "cymru_scout")
MAX_FINGERPRINTS = 50


class Fingerprint(BaseModel):
    """An infrastructure fingerprint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: FingerprintKind
    value: str = Field(min_length=1, max_length=1024)

    @field_validator("value", mode="before")
    @classmethod
    def _strip(cls, value: Any) -> Any:
        """Accept numbers (ASNs) and strip the blanks around values."""
        return str(value).strip() if isinstance(value, (str, int)) else value

    @property
    def asn(self) -> int:
        """Return the number of an ``asn`` fingerprint (``AS13335`` or ``13335``)."""
        digits = self.value.upper().removeprefix("AS")
        return int(digits)


class FingerprintRule(BaseModel):
    """The native query of an infrastructure hunt."""

    model_config = ConfigDict(extra="forbid")

    fingerprints: list[Fingerprint] = Field(
        default_factory=list, max_length=MAX_FINGERPRINTS
    )
    sources: list[SourceName] | None = None
    queries: dict[SourceName, str] = Field(default_factory=dict)

    @field_validator("fingerprints")
    @classmethod
    def _check_asns(cls, value: list[Fingerprint]) -> list[Fingerprint]:
        """Reject ASN fingerprints that are not numbers."""
        for fingerprint in value:
            if fingerprint.kind == "asn":
                digits = fingerprint.value.upper().removeprefix("AS")
                if not digits.isdigit():
                    raise ValueError(f"'{fingerprint.value}' is not an ASN.")
        return value


def parse_rule(text: str) -> FingerprintRule:
    """Parse the fingerprint rule of an infrastructure hunt.

    Args:
        text: YAML or JSON document.

    Returns:
        The validated rule.

    Raises:
        HuntTranslationError: If the document is not a valid fingerprint rule.
    """
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as err:
        raise HuntTranslationError(
            f"The infrastructure rule is not valid YAML: {err}"
        ) from err
    if not isinstance(document, dict):
        raise HuntTranslationError(
            "The infrastructure rule must be a YAML mapping with 'fingerprints', "
            "and optionally 'sources' and 'queries'."
        )
    try:
        rule = FingerprintRule.model_validate(document)
    except ValidationError as err:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or 'rule'}: {error['msg']}"
            for error in err.errors()
        )
        raise HuntTranslationError(f"Invalid infrastructure rule: {details}") from err
    if not rule.fingerprints and not any(q.strip() for q in rule.queries.values()):
        raise HuntTranslationError(
            "The infrastructure rule has no fingerprint and no query."
        )
    return rule


def _quoted(value: str) -> str:
    """Quote a value with double quotes, escaping backslashes and quotes."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _field(name: str) -> Callable[[Fingerprint], str]:
    """Build an exact match on a field."""
    return lambda fingerprint: f"{name} = {_quoted(fingerprint.value)}"


def _lucene_field(name: str) -> Callable[[Fingerprint], str]:
    """Build a phrase match on a Lucene field."""
    return lambda fingerprint: f"{name}:{_quoted(fingerprint.value)}"


CENSYS_FIELDS: dict[str, Callable[[Fingerprint], str]] = {
    "jarm": _field("host.services.jarm.fingerprint"),
    "ja4x": _field("host.services.cert.parsed.ja4x"),
    "ja4s": _field("host.services.tls.ja4s"),
    "certificate_sha256": _field("host.services.cert.fingerprint_sha256"),
    "certificate_subject": _field("host.services.cert.parsed.subject_dn"),
    "certificate_issuer": _field("host.services.cert.parsed.issuer_dn"),
    "http_title": _field("host.services.endpoints.http.html_title"),
    "http_body_sha256": _field("host.services.endpoints.http.body_hash_sha256"),
    "http_server": lambda fingerprint: (
        "host.services.endpoints.http.headers: "
        f'(key = "Server" and value = {_quoted(fingerprint.value)})'
    ),
    "banner_sha256": _field("host.services.banner_hash_sha256"),
    "asn": lambda fingerprint: f'host.autonomous_system.asn = "{fingerprint.asn}"',
}
"""Censys Query Language (CenQL) match of each fingerprint kind on hosts."""

SILENTPUSH_FIELDS: dict[str, Callable[[Fingerprint], str]] = {
    "jarm": _field("jarm"),
    "certificate_sha256": _field("ssl.SHA256"),
    "http_title": _field("htmltitle"),
    "http_body_sha256": _field("html_body_sha256"),
    "http_server": _field("header.server"),
}
"""Silent Push Query Language (SPQL) match of each fingerprint kind on web scans."""

URLSCAN_FIELDS: dict[str, Callable[[Fingerprint], str]] = {
    "http_title": _lucene_field("page.title"),
    "http_server": _lucene_field("page.server"),
    "certificate_issuer": _lucene_field("page.tlsIssuer"),
    "http_body_sha256": lambda fingerprint: f"hash:{fingerprint.value.lower()}",
    "asn": lambda fingerprint: f"page.asn:AS{fingerprint.asn}",
}
"""urlscan.io search query match of each fingerprint kind on scans."""

SCOUT_KINDS = frozenset({"jarm", "ja4x", "ja4s", "certificate_sha256"})
"""Fingerprint kinds Team Cymru Scout finds with a value search."""

QUERY_JOINS = {"censys": " or ", "silentpush": " OR ", "urlscan": " OR "}
SOURCE_FIELDS = {
    "censys": CENSYS_FIELDS,
    "silentpush": SILENTPUSH_FIELDS,
    "urlscan": URLSCAN_FIELDS,
}


def source_queries(rule: FingerprintRule, source: str) -> list[str]:
    """Return the queries a source runs for a rule.

    Args:
        rule: Fingerprint rule.
        source: Source name.

    Returns:
        The queries, empty when the source cannot search any fingerprint.
    """
    queries: list[str] = []
    if source == "cymru_scout":
        queries = [
            fingerprint.value
            for fingerprint in rule.fingerprints
            if fingerprint.kind in SCOUT_KINDS
        ]
    else:
        builders = SOURCE_FIELDS[source]
        matches = [
            builders[fingerprint.kind](fingerprint)
            for fingerprint in rule.fingerprints
            if fingerprint.kind in builders
        ]
        if matches:
            queries.append(_join(matches, QUERY_JOINS[source]))
    raw = dict(rule.queries).get(source, "").strip()
    if raw:
        queries.append(raw)
    return list(dict.fromkeys(queries))


def _join(matches: list[str], operator: str) -> str:
    """Join matches with a boolean operator."""
    if len(matches) == 1:
        return matches[0]
    return operator.join(f"({match})" for match in matches)


def build_plan(
    rule: FingerprintRule, configured: Iterable[str]
) -> dict[str, list[str]]:
    """Return the queries of every source the rule runs on.

    Args:
        rule: Fingerprint rule.
        configured: Sources with credentials.

    Returns:
        The queries by source, in source order.

    Raises:
        HuntTranslationError: If no configured source can run the rule.
    """
    available = [source for source in SOURCES if source in set(configured)]
    selected = [s for s in available if rule.sources is None or s in rule.sources]
    if not selected:
        requested = ", ".join(rule.sources or [])
        raise HuntTranslationError(
            f"None of the sources of the rule ({requested}) is configured "
            f"(configured: {', '.join(available)})."
        )
    plan = {source: source_queries(rule, source) for source in selected}
    plan = {source: queries for source, queries in plan.items() if queries}
    if not plan:
        kinds = ", ".join(sorted({f.kind for f in rule.fingerprints}))
        raise HuntTranslationError(
            f"No configured source searches the fingerprints of the rule ({kinds}): "
            f"configure a source supporting them or add a raw query."
        )
    return plan


def render_plan(plan: dict[str, list[str]]) -> str:
    """Render the queries of a plan (the query executed and shown in OpenCTI)."""
    return json.dumps(plan, indent=2, ensure_ascii=False)


def load_plan(text: str) -> dict[str, list[str]]:
    """Load a plan rendered by :func:`render_plan`.

    Raises:
        HuntTranslationError: If the text is not a plan.
    """
    try:
        plan = json.loads(text)
    except ValueError as err:
        raise HuntTranslationError("The infrastructure query plan is invalid.") from err
    if not isinstance(plan, dict) or not all(
        source in SOURCES
        and isinstance(queries, list)
        and all(isinstance(query, str) for query in queries)
        for source, queries in plan.items()
    ):
        raise HuntTranslationError("The infrastructure query plan is invalid.")
    return plan
