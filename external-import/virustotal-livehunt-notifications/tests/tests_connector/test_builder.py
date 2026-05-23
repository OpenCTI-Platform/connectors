"""Unit tests pinning the malware-config / indicator-creation additions.

These tests exercise the *pure* helpers added on top of the master
``LivehuntBuilder`` so we can pin their contract without standing up
the full builder (which needs a live VirusTotal client + OpenCTI
helper). The helpers covered here are:

* :func:`livehunt.builder._escape_stix_pattern_value`
* :func:`LivehuntBuilder._is_valid_domain_name`
* :func:`LivehuntBuilder._ip_version`
* :func:`LivehuntBuilder._unique_strings`

The malware-config bundle-builder methods (``_extract_malware_config``,
``_create_malware_config_indicator``, ``_create_file_indicator``) are
instance methods that mutate ``self.bundle``; they are exercised
below via a ``LivehuntBuilder`` built with ``__new__`` and minimal
mock attributes so we can pin the bundle-contents contract without
the full ``__init__`` dependency surface (live VT client / OpenCTI
helper / SDK plumbing).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import stix2
from livehunt.builder import LivehuntBuilder, _escape_stix_pattern_value


class TestEscapeStixPatternValue:
    """STIX pattern values must escape backslashes and single quotes.

    Without this, IOCs containing either character produce a malformed
    pattern AND a mismatched deterministic indicator id, which silently
    drops the indicator on import.
    """

    def test_escape_single_quote(self):
        assert _escape_stix_pattern_value("a'b") == "a\\'b"

    def test_escape_backslash(self):
        assert _escape_stix_pattern_value("a\\b") == "a\\\\b"

    def test_escape_quote_and_backslash(self):
        assert _escape_stix_pattern_value("a\\b'c") == "a\\\\b\\'c"

    def test_no_escape_when_clean(self):
        assert _escape_stix_pattern_value("evil.example.com") == "evil.example.com"


class TestIsValidDomainName:
    """Domain validation must be regex-only — no live DNS resolution.

    Live DNS queries (e.g. via ``dns.google``) drop valid C2 domains
    that are NXDOMAIN, blocked by network policy, or AAAA-only, and
    add per-host latency to processing.
    """

    @pytest.mark.parametrize(
        "domain",
        [
            "evil.example.com",
            "a.b.example.org",
            "xn--bcher-kva.example",  # IDN-encoded SLD
            "1.example.com",
            # Punycode TLDs (RFC 1123 allows alphanumeric + hyphen in
            # every label, TLD included). A previous revision pinned
            # the TLD to ``[a-zA-Z]{2,63}`` and silently dropped
            # IOCs that pointed at these.
            "example.xn--p1ai",
            "example.xn--80akhbyknj4f",
            "c2.example.xn--p1ai",
            # ccTLDs containing digits in their label are still rare
            # in practice but are not forbidden by RFC 1123 — the
            # validator no longer rejects them outright.
            "host.a1.example",
        ],
    )
    def test_valid_domains(self, domain: str) -> None:
        assert LivehuntBuilder._is_valid_domain_name(domain) is True

    @pytest.mark.parametrize(
        "domain",
        [
            "",
            "noTLD",
            "-leading-dash.example.com",
            "example.com/path",
            "evil.example.com.",
            "http://evil.example.com",
            "evil. example.com",
            # RFC 1123 forbids a leading hyphen on **every** label, not
            # only the first. Pin the per-label rule explicitly so a
            # regex regression cannot let these through.
            "a.-b.com",
            "evil.-sub.example.com",
            # And a trailing hyphen on any label is forbidden too.
            "a.b-.com",
            "evil.sub-.example.com",
            "trailing-.example.com",
        ],
    )
    def test_invalid_domains(self, domain: str) -> None:
        assert LivehuntBuilder._is_valid_domain_name(domain) is False


class TestIpVersion:
    """``_ip_version`` returns 4 / 6 for valid addresses, None otherwise."""

    @pytest.mark.parametrize(
        "address, version",
        [
            ("1.2.3.4", 4),
            ("10.0.0.1", 4),
            ("::1", 6),
            ("2001:db8::1", 6),
            ("fe80::1", 6),
        ],
    )
    def test_valid(self, address: str, version: int) -> None:
        assert LivehuntBuilder._ip_version(address) == version

    @pytest.mark.parametrize(
        "address",
        [
            "",
            "not-an-ip",
            "256.0.0.1",
            "1.2.3",
            ":::::::",
        ],
    )
    def test_invalid(self, address: str) -> None:
        assert LivehuntBuilder._ip_version(address) is None


class TestUniqueStrings:
    """Deduplicate, strip, drop empties and non-strings."""

    def test_dedup_preserves_order(self) -> None:
        assert LivehuntBuilder._unique_strings(["a", "b", "a", "c", "b"]) == [
            "a",
            "b",
            "c",
        ]

    def test_strips_whitespace_and_drops_empty(self) -> None:
        assert LivehuntBuilder._unique_strings(["  a  ", "", "   ", "b"]) == ["a", "b"]

    def test_drops_non_strings(self) -> None:
        assert LivehuntBuilder._unique_strings(["a", 1, None, "b", b"c"]) == ["a", "b"]

    def test_none_and_empty_input(self) -> None:
        assert LivehuntBuilder._unique_strings(None) == []
        assert LivehuntBuilder._unique_strings([]) == []


# ---------------------------------------------------------------------------
# Bundle-builder helpers (``_extract_malware_config``,
# ``_create_malware_config_indicator``, ``_create_file_indicator``)
# ---------------------------------------------------------------------------


_AUTHOR_ID = "identity--00000000-0000-4000-8000-000000000001"


def _make_builder(
    *,
    create_file_indicators: bool = False,
    create_domain_name_indicators: bool = False,
    create_ip_indicators: bool = False,
    create_url_indicators: bool = False,
) -> LivehuntBuilder:
    """Build a ``LivehuntBuilder`` with only the attributes the helpers read.

    The full ``__init__`` requires a live VirusTotal client + an
    ``OpenCTIConnectorHelper`` + an Identity / Marking, which is too
    heavy for a unit test. ``__new__`` bypasses the constructor; the
    handful of attributes the bundle helpers actually touch are
    injected manually below.
    """

    builder = LivehuntBuilder.__new__(LivehuntBuilder)
    author = stix2.Identity(
        id=_AUTHOR_ID, name="Test Author", identity_class="organization"
    )
    tlp_marking = stix2.TLP_AMBER
    builder.author = author
    builder.tlp_marking = tlp_marking
    builder._default_bundle = [author, tlp_marking]
    builder.bundle = builder._default_bundle.copy()
    builder.create_file_indicators = create_file_indicators
    builder.create_domain_name_indicators = create_domain_name_indicators
    builder.create_ip_indicators = create_ip_indicators
    builder.create_url_indicators = create_url_indicators
    # ``self.client`` is only called by ``_extract_malware_config``,
    # the individual tests below override ``.get_object`` per case.
    builder.client = MagicMock()
    # ``_create_*`` helpers go through ``self.helper.api.stix2.format_date``.
    # Match pycti's canonical shape (``YYYY-MM-DDTHH:MM:SS.mmmZ``) so
    # ``stix2.Indicator(valid_from=...)`` parses it without raising.
    builder.helper = MagicMock()
    builder.helper.api.stix2.format_date = lambda d: d.strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )
    return builder


class TestCreateFileIndicator:
    """``_create_file_indicator`` emits one Indicator + based-on edge.

    When an ``incident_id`` is provided, an extra ``related-to`` edge
    from the incident to the indicator is appended so the alert page
    surfaces the indicator. Author / TLP marking propagate to every
    object.
    """

    def _file_id(self) -> str:
        return "file--00000000-0000-4000-8000-000000000010"

    def _vtobj(self) -> SimpleNamespace:
        return SimpleNamespace(
            sha256="b" * 64,
        )

    def test_creates_indicator_and_based_on_without_incident(self) -> None:
        builder = _make_builder()
        builder._create_file_indicator(
            self._vtobj(), incident_id=None, file_id=self._file_id()
        )
        objs = builder.bundle[len(builder._default_bundle) :]
        # One Indicator + one based-on relationship.
        assert len(objs) == 2
        indicator, based_on = objs
        assert indicator.type == "indicator"
        assert indicator.pattern.startswith("[file:hashes.'SHA-256' = '")
        assert indicator.pattern_type == "stix"
        assert indicator.created_by_ref == _AUTHOR_ID
        assert stix2.TLP_AMBER.id in indicator.object_marking_refs
        # ``based-on`` from the indicator to the file observable.
        assert based_on.relationship_type == "based-on"
        assert based_on.source_ref == indicator["id"]
        assert based_on.target_ref == self._file_id()
        assert stix2.TLP_AMBER.id in based_on.object_marking_refs

    def test_creates_extra_related_to_when_incident(self) -> None:
        incident_id = "incident--00000000-0000-4000-8000-000000000020"
        builder = _make_builder()
        builder._create_file_indicator(
            self._vtobj(), incident_id=incident_id, file_id=self._file_id()
        )
        objs = builder.bundle[len(builder._default_bundle) :]
        # Indicator + based-on + related-to(incident → indicator).
        assert len(objs) == 3
        related_to = objs[2]
        assert related_to.relationship_type == "related-to"
        assert related_to.source_ref == incident_id
        assert related_to.target_ref == objs[0]["id"]


class TestCreateMalwareConfigIndicator:
    """``_create_malware_config_indicator`` mirrors the file-indicator shape.

    Same contract: one Indicator + based-on edge to the observable
    (and a related-to from the incident when present). Author / TLP
    propagate, and the OpenCTI main-observable-type custom property
    matches the per-type argument.
    """

    def test_indicator_for_domain_observable(self) -> None:
        builder = _make_builder(create_domain_name_indicators=True)
        observable = stix2.DomainName(
            value="evil.example.com",
            object_marking_refs=[stix2.TLP_AMBER],
            allow_custom=True,
        )
        builder._create_malware_config_indicator(
            observable,
            "domain-name",
            "Domain-Name",
            incident_id=None,
        )
        objs = builder.bundle[len(builder._default_bundle) :]
        assert len(objs) == 2
        indicator, based_on = objs
        assert indicator.pattern == "[domain-name:value = 'evil.example.com']"
        assert (
            indicator.x_opencti_main_observable_type == "Domain-Name"
        )  # type: ignore[attr-defined]
        assert based_on.relationship_type == "based-on"
        assert based_on.target_ref == observable.id

    def test_indicator_for_url_observable_escapes_quote(self) -> None:
        builder = _make_builder(create_url_indicators=True)
        # URL with a single quote — must be escaped in the pattern AND
        # produce a deterministic id consistent with the escaped value.
        observable = stix2.URL(
            value="https://evil.example.org/a?q='b'",
            object_marking_refs=[stix2.TLP_AMBER],
            allow_custom=True,
        )
        builder._create_malware_config_indicator(
            observable, "url", "Url", incident_id=None
        )
        indicator = builder.bundle[len(builder._default_bundle)]
        # Single quotes escaped inside the pattern.
        assert "?q=\\'b\\'" in indicator.pattern

    def test_extra_related_to_when_incident(self) -> None:
        incident_id = "incident--00000000-0000-4000-8000-000000000030"
        builder = _make_builder(create_ip_indicators=True)
        observable = stix2.IPv4Address(
            value="1.2.3.4",
            object_marking_refs=[stix2.TLP_AMBER],
            allow_custom=True,
        )
        builder._create_malware_config_indicator(
            observable, "ipv4-addr", "IPv4-Addr", incident_id=incident_id
        )
        objs = builder.bundle[len(builder._default_bundle) :]
        assert len(objs) == 3
        related_to = objs[2]
        assert related_to.relationship_type == "related-to"
        assert related_to.source_ref == incident_id


class TestExtractMalwareConfig:
    """End-to-end: ``_extract_malware_config`` appends observables + relations.

    The VT client is stubbed; we assert the bundle contains exactly
    the observables / relationships / indicators the configured flags
    request and that author + TLP marking propagate to every object.
    """

    def _vtobj(self) -> SimpleNamespace:
        return SimpleNamespace(sha256="c" * 64)

    def _stub_config_response(self, builder: LivehuntBuilder, payload: dict) -> None:
        """Make ``client.get_object`` return a SimpleNamespace exposing the payload."""
        builder.client.get_object.return_value = SimpleNamespace(
            malware_configurations=payload
        )

    def test_no_indicators_when_flags_off(self) -> None:
        """Observables are still appended; Indicators only when flag is on."""
        builder = _make_builder()
        self._stub_config_response(
            builder,
            {
                "domains": ["evil.example.com"],
                "ips": ["1.2.3.4"],
                "urls": ["https://evil.example.org/path"],
            },
        )
        builder._extract_malware_config(
            self._vtobj(),
            incident_id=None,
            file_id="file--00000000-0000-4000-8000-000000000010",
        )
        kinds = [obj.type for obj in builder.bundle[len(builder._default_bundle) :]]
        # 3 observables + 3 related-to edges (one per observable) and
        # NO indicators (every ``create_*_indicators`` flag is off).
        assert kinds.count("indicator") == 0
        assert kinds.count("domain-name") == 1
        assert kinds.count("ipv4-addr") == 1
        assert kinds.count("url") == 1
        assert kinds.count("relationship") == 3

    def test_per_type_indicators_emitted_when_flag_on(self) -> None:
        builder = _make_builder(
            create_domain_name_indicators=True,
            create_ip_indicators=True,
            create_url_indicators=True,
        )
        self._stub_config_response(
            builder,
            {
                "domains": ["evil.example.com"],
                "ips": ["1.2.3.4", "2001:db8::1"],
                "urls": ["https://evil.example.org/path"],
            },
        )
        builder._extract_malware_config(
            self._vtobj(),
            incident_id=None,
            file_id="file--00000000-0000-4000-8000-000000000010",
        )
        objs = builder.bundle[len(builder._default_bundle) :]
        kinds = [o.type for o in objs]
        # 1 domain + 2 ips (one v4, one v6) + 1 url = 4 observables.
        assert kinds.count("domain-name") == 1
        assert kinds.count("ipv4-addr") == 1
        assert kinds.count("ipv6-addr") == 1
        assert kinds.count("url") == 1
        # 4 indicators (one per observable) and 4 ``related-to`` +
        # 4 ``based-on`` = 8 relationships.
        assert kinds.count("indicator") == 4
        assert kinds.count("relationship") == 8
        # Every emitted SDO carries the configured TLP marking.
        for obj in objs:
            assert stix2.TLP_AMBER.id in obj.object_marking_refs

    def test_invalid_domain_and_ip_silently_skipped(self) -> None:
        builder = _make_builder(
            create_domain_name_indicators=True,
            create_ip_indicators=True,
        )
        self._stub_config_response(
            builder,
            {
                "domains": ["a.-b.com", "evil.example.com"],
                "ips": ["256.256.256.256", "1.2.3.4"],
                "urls": [],
            },
        )
        builder._extract_malware_config(
            self._vtobj(),
            incident_id=None,
            file_id="file--00000000-0000-4000-8000-000000000010",
        )
        objs = builder.bundle[len(builder._default_bundle) :]
        kinds = [o.type for o in objs]
        # Only the valid domain + valid IPv4 should land in the bundle.
        assert kinds.count("domain-name") == 1
        assert kinds.count("ipv4-addr") == 1
        # No malformed-input observables.
        assert kinds.count("ipv6-addr") == 0
        assert kinds.count("url") == 0

    def test_no_op_on_vt_client_exception(self) -> None:
        """A VT API error must not blow up the run — bundle stays clean."""
        builder = _make_builder(create_domain_name_indicators=True)
        builder.client.get_object.side_effect = RuntimeError("boom")
        # Required for the warning log emitted on the exception path.
        builder.helper.connector_logger = MagicMock()
        builder._extract_malware_config(
            self._vtobj(),
            incident_id=None,
            file_id="file--00000000-0000-4000-8000-000000000010",
        )
        # Bundle still only contains the defaults (no observable / no
        # indicator was appended).
        assert len(builder.bundle) == len(builder._default_bundle)
        builder.helper.connector_logger.warning.assert_called_once()

    def test_relationships_link_back_to_incident_when_present(self) -> None:
        incident_id = "incident--00000000-0000-4000-8000-000000000020"
        builder = _make_builder()
        self._stub_config_response(builder, {"domains": ["evil.example.com"]})
        builder._extract_malware_config(
            self._vtobj(),
            incident_id=incident_id,
            file_id="file--00000000-0000-4000-8000-000000000010",
        )
        objs = builder.bundle[len(builder._default_bundle) :]
        # 1 observable + 2 ``related-to`` edges (file → observable,
        # incident → observable).
        relationships = [o for o in objs if o.type == "relationship"]
        assert len(relationships) == 2
        sources = {r.source_ref for r in relationships}
        assert incident_id in sources
