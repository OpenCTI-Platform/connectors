"""Fingerprint documents of infrastructure hunts.

An infrastructure hunt runs on internet scanning services (the platforms of
``HUNT_INFRASTRUCTURE_PLATFORMS``). Its native query, in the ``fingerprint``
language, is a YAML (or JSON) document listing the fingerprints of the
adversary infrastructure, with optional raw queries per platform::

    fingerprints:
      - kind: jarm
        value: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
      - kind: certificate_subject
        value: CN=Major Cobalt Strike, OU=AdvancedPenTesting, O=cobaltstrike
    queries:
      urlscan: 'page.title:"Login" AND page.asn:AS20473'

Each connector searches the fingerprint kinds its service indexes, and runs the
raw query written for its platform.
"""

import json
from collections.abc import Sequence
from typing import Any, Literal

import yaml
from connectors_sdk.connectors.internal_hunt.errors import HuntTranslationError
from connectors_sdk.settings.base_settings import HUNT_INFRASTRUCTURE_PLATFORMS
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

FINGERPRINT_LANGUAGE = "fingerprint"
"""Language of the native queries of infrastructure hunts."""

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
"""Kinds of infrastructure fingerprints."""

MAX_FINGERPRINTS = 50
"""Maximum number of fingerprints of a document."""

FINGERPRINT_FIELDS: dict[str, str] = {
    "jarm": "jarm",
    "ja4x": "ja4x",
    "ja4s": "ja4s",
    "certificate_sha256": "certificate.sha256",
    "certificate_subject": "certificate.subject",
    "certificate_issuer": "certificate.issuer",
    "http_title": "http.title",
    "http_body_sha256": "http.body_sha256",
    "http_server": "http.server",
    "banner_sha256": "banner_sha256",
    "asn": "asn",
}
"""Host event field holding the values of each fingerprint kind."""


class Fingerprint(BaseModel):
    """An infrastructure fingerprint.

    Attributes:
        kind: Kind of the fingerprint.
        value: Value searched (an ASN is ``13335`` or ``AS13335``).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: FingerprintKind
    value: str = Field(min_length=1, max_length=1024)

    @field_validator("value", mode="before")
    @classmethod
    def _strip(cls, value: Any) -> Any:
        """Accept numbers (ASNs) and strip the blanks around values."""
        if isinstance(value, bool):
            return value
        return str(value).strip() if isinstance(value, (str, int)) else value

    @property
    def asn(self) -> int:
        """Return the number of an ``asn`` fingerprint."""
        return int(self.value.upper().removeprefix("AS"))


class FingerprintRule(BaseModel):
    """The native query of an infrastructure hunt.

    Attributes:
        fingerprints: Fingerprints of the infrastructure.
        queries: Raw queries in the language of each platform, by platform slug.
    """

    model_config = ConfigDict(extra="forbid")

    fingerprints: list[Fingerprint] = Field(
        default_factory=list, max_length=MAX_FINGERPRINTS
    )
    queries: dict[str, str] = Field(default_factory=dict)

    @field_validator("fingerprints")
    @classmethod
    def _check_asns(cls, value: list[Fingerprint]) -> list[Fingerprint]:
        """Reject ASN fingerprints that are not numbers."""
        for fingerprint in value:
            digits = fingerprint.value.upper().removeprefix("AS")
            if fingerprint.kind == "asn" and not digits.isdigit():
                raise ValueError(f"'{fingerprint.value}' is not an ASN.")
        return value

    @field_validator("queries")
    @classmethod
    def _check_platforms(cls, value: dict[str, str]) -> dict[str, str]:
        """Accept raw queries for the internet scanning platforms only."""
        unknown = sorted(set(value) - set(HUNT_INFRASTRUCTURE_PLATFORMS))
        if unknown:
            raise ValueError(
                f"unknown platform(s) {', '.join(unknown)}; expected: "
                f"{', '.join(HUNT_INFRASTRUCTURE_PLATFORMS)}."
            )
        return value

    def raw_query(self, platform: str) -> str:
        """Return the raw query of a platform (empty when none)."""
        return self.queries.get(platform, "").strip()

    def of_kinds(self, kinds: Sequence[str]) -> list[Fingerprint]:
        """Return the fingerprints of some kinds, in document order."""
        return [fp for fp in self.fingerprints if fp.kind in kinds]


def parse_fingerprint_rule(text: str) -> FingerprintRule:
    """Parse the fingerprint document of an infrastructure hunt.

    Args:
        text: YAML or JSON document.

    Returns:
        The validated document.

    Raises:
        HuntTranslationError: If the text is not a valid fingerprint document.
    """
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as err:
        raise HuntTranslationError(
            f"The fingerprint document is not valid YAML: {err}"
        ) from err
    if not isinstance(document, dict):
        raise HuntTranslationError(
            "The fingerprint document must be a YAML mapping with 'fingerprints' "
            "and, optionally, 'queries'."
        )
    try:
        rule = FingerprintRule.model_validate(document)
    except ValidationError as err:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or 'document'}: {error['msg']}"
            for error in err.errors()
        )
        raise HuntTranslationError(f"Invalid fingerprint document: {details}") from err
    if not rule.fingerprints and not any(q.strip() for q in rule.queries.values()):
        raise HuntTranslationError(
            "The fingerprint document has no fingerprint and no query."
        )
    return rule


def describe_fingerprints(rule: FingerprintRule, max_items: int = 5) -> str:
    """Describe the fingerprints of a document in a few words.

    Args:
        rule: Fingerprint document.
        max_items: Number of fingerprints named.

    Returns:
        The kinds and values of the first fingerprints, and the platforms of the raw queries.
    """
    parts = [f"{fp.kind} {fp.value}" for fp in rule.fingerprints[:max_items]]
    if len(rule.fingerprints) > max_items:
        parts.append(f"{len(rule.fingerprints) - max_items} more")
    if rule.queries:
        parts.append(f"queries on {', '.join(sorted(rule.queries))}")
    return ", ".join(parts)


def quote_value(value: str) -> str:
    """Quote a value with double quotes, escaping backslashes and double quotes."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def join_matches(matches: Sequence[str], operator: str) -> str:
    """Join matches with a boolean operator, each in parentheses when there are several."""
    if len(matches) == 1:
        return matches[0]
    return operator.join(f"({match})" for match in matches)


def render_queries(queries: Sequence[str]) -> str:
    """Render the queries of a run as JSON (the query reported to OpenCTI)."""
    return json.dumps(list(queries), indent=2, ensure_ascii=False)


def load_queries(text: str) -> list[str]:
    """Load queries rendered by :func:`render_queries`.

    Raises:
        HuntTranslationError: If the text is not a list of queries.
    """
    try:
        queries = json.loads(text)
    except ValueError as err:
        raise HuntTranslationError("The infrastructure queries are invalid.") from err
    if not isinstance(queries, list) or not all(
        isinstance(query, str) and query.strip() for query in queries
    ):
        raise HuntTranslationError("The infrastructure queries are invalid.")
    return queries
