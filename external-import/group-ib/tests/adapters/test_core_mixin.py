from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from adapters.adapter import DataToSTIXAdapter
from connector.settings import ConfigConnector

# --- Adapter factory ---------------------------------------------------------


def _adapter(
    collection: str = "apt/threat",
    tlp_color: str = "amber",
    is_ioc: bool = True,
    threat_actor_name: str | None = None,
) -> DataToSTIXAdapter:
    """Build a real ``DataToSTIXAdapter`` with a mock helper.

    The constructor only needs ``helper.connector_logger`` — there's no
    network or filesystem I/O on the adapter side.
    """
    helper = SimpleNamespace(connector_logger=MagicMock())
    return DataToSTIXAdapter(
        mitre_mapper={},
        collection=collection,
        tlp_color=tlp_color,
        helper=helper,
        is_ioc=is_ioc,
        threat_actor_name=threat_actor_name,
        config=ConfigConnector(),
    )


# --- Tiny static helpers -----------------------------------------------------


class TestNormalizeList:
    def test_none(self):
        a = _adapter()
        assert a._normalize_list(None) == []

    def test_empty(self):
        a = _adapter()
        assert a._normalize_list("") == []
        assert a._normalize_list(0) == []
        assert a._normalize_list([]) == []

    def test_list_passes_through(self):
        a = _adapter()
        assert a._normalize_list([1, 2]) == [1, 2]

    def test_scalar_wrapped(self):
        a = _adapter()
        assert a._normalize_list("x") == ["x"]
        assert a._normalize_list({"k": 1}) == [{"k": 1}]


class TestFlattenCell:
    def test_none(self):
        a = _adapter()
        assert a._flatten_cell(None) == ""

    def test_string(self):
        a = _adapter()
        assert a._flatten_cell("hello") == "hello"

    def test_single_element_list(self):
        a = _adapter()
        assert a._flatten_cell(["one"]) == "one"

    def test_empty_list(self):
        a = _adapter()
        assert a._flatten_cell([]) == ""

    def test_multi_element_list_joined(self):
        a = _adapter()
        assert a._flatten_cell(["a", "b", "c"]) == "a, b, c"

    def test_int(self):
        a = _adapter()
        assert a._flatten_cell(42) == "42"


class TestExtractNameList:
    def test_none(self):
        a = _adapter()
        assert a._extract_name_list(None) == []

    def test_list_of_dicts_uses_name(self):
        a = _adapter()
        out = a._extract_name_list([{"name": "x"}, {"name": "y"}, {"title": "z"}])
        assert out == ["x", "y", "z"]

    def test_list_of_strings(self):
        a = _adapter()
        assert a._extract_name_list(["a", "b"]) == ["a", "b"]

    def test_dict_without_name_or_title_skipped(self):
        a = _adapter()
        assert a._extract_name_list([{"foo": "bar"}]) == []

    def test_scalar_input_wrapped(self):
        # ``_normalize_list`` wraps scalars, then the str-branch picks it up.
        a = _adapter()
        assert a._extract_name_list("single") == ["single"]


class TestExtractStringValue:
    def test_dict_value(self):
        a = _adapter()
        assert a._extract_string_value({"value": "x"}) == "x"

    def test_dict_hash_fallback(self):
        a = _adapter()
        assert a._extract_string_value({"hash": "abc"}) == "abc"

    def test_dict_domain_fallback(self):
        a = _adapter()
        assert a._extract_string_value({"domain": "example.com"}) == "example.com"

    def test_dict_first_field_wins(self):
        a = _adapter()
        assert (
            a._extract_string_value({"value": "v", "hash": "h", "domain": "d"}) == "v"
        )

    def test_string_input(self):
        a = _adapter()
        assert a._extract_string_value("  raw  ") == "raw"

    def test_empty_string_returns_none(self):
        a = _adapter()
        assert a._extract_string_value("   ") is None

    def test_none_returns_none(self):
        a = _adapter()
        assert a._extract_string_value(None) is None

    def test_int_returns_none(self):
        # Non-dict, non-str → None.
        a = _adapter()
        assert a._extract_string_value(42) is None


# --- Validators -------------------------------------------------------------


class TestIsValidDomain:
    def test_plain_fqdn_accepted(self):
        a = _adapter()
        assert a.is_valid_domain("example.com") is True

    def test_too_long(self):
        a = _adapter()
        assert a.is_valid_domain("a" * 254) is False

    def test_with_scheme_rejected(self):
        a = _adapter()
        assert a.is_valid_domain("http://example.com") is False

    def test_with_path_rejected(self):
        a = _adapter()
        assert a.is_valid_domain("example.com/path") is False

    def test_with_space_rejected(self):
        a = _adapter()
        assert a.is_valid_domain("x . com") is False

    def test_non_string(self):
        a = _adapter()
        assert a.is_valid_domain(42) is False
        assert a.is_valid_domain(None) is False

    def test_empty(self):
        a = _adapter()
        assert a.is_valid_domain("") is False


class TestIsValidUrl:
    def test_http(self):
        a = _adapter()
        assert a.is_valid_url("http://example.com/path") is True

    def test_https(self):
        a = _adapter()
        assert a.is_valid_url("https://example.com") is True

    def test_ftp(self):
        a = _adapter()
        assert a.is_valid_url("ftp://example.com/file") is True
        assert a.is_valid_url("ftps://example.com/file") is True

    def test_no_scheme_rejected(self):
        a = _adapter()
        assert a.is_valid_url("example.com/path") is False

    def test_space_rejected(self):
        a = _adapter()
        assert a.is_valid_url("https://example.com/with space") is False

    def test_non_string(self):
        a = _adapter()
        assert a.is_valid_url(42) is False


class TestIsValidEmail:
    def test_valid(self):
        a = _adapter()
        assert a.is_valid_email("alice@example.com") is True

    def test_brackets_stripped(self):
        # The validator strips ``<>`` wrappers before checking.
        a = _adapter()
        assert a.is_valid_email("<a@example.com>") is True

    def test_too_long(self):
        a = _adapter()
        assert a.is_valid_email("a" * 250 + "@example.com") is False

    def test_invalid_format(self):
        a = _adapter()
        assert a.is_valid_email("no-at-sign") is False

    def test_non_string(self):
        a = _adapter()
        assert a.is_valid_email(None) is False


class TestNormalizeEmail:
    def test_canonical_form(self):
        a = _adapter()
        assert a.normalize_email("Alice@EXAMPLE.com") == "Alice@example.com"

    def test_local_part_case_preserved(self):
        a = _adapter()
        # Only the domain is lowercased.
        assert a.normalize_email("CaseSensitive@A.B") == "CaseSensitive@a.b"

    def test_brackets_stripped(self):
        a = _adapter()
        assert a.normalize_email("<a@example.com>") == "a@example.com"

    def test_invalid_returns_none(self):
        a = _adapter()
        assert a.normalize_email("no-at") is None

    def test_none_returns_none(self):
        a = _adapter()
        assert a.normalize_email(None) is None


class TestIsIpvX:
    def test_ipv4(self):
        a = _adapter()
        assert a.is_ipv4("192.0.2.1") is True
        assert a.is_ipv4("256.1.1.1") is False

    def test_ipv6(self):
        a = _adapter()
        assert a.is_ipv6("::1") is True
        assert a.is_ipv6("192.0.2.1") is False


class TestValidHash:
    def test_valid_md5(self):
        a = _adapter()
        assert a._valid_hash("d41d8cd98f00b204e9800998ecf8427e", "MD5") is True

    def test_invalid_md5(self):
        a = _adapter()
        assert a._valid_hash("not-a-hash", "MD5") is False

    def test_valid_sha1(self):
        a = _adapter()
        h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert a._valid_hash(h, "SHA-1") is True

    def test_valid_sha256(self):
        a = _adapter()
        h = "e3b0c44298fc1c149afbf4c8996fb924" "27ae41e4649b934ca495991b7852b855"
        assert a._valid_hash(h, "SHA-256") is True


# --- Severity / TLP / global label ------------------------------------------


class TestMapSeverity:
    def test_known_colours(self):
        a = _adapter()
        assert a._map_severity("red") == "critical"
        assert a._map_severity("orange") == "high"
        assert a._map_severity("amber") == "high"
        assert a._map_severity("yellow") == "medium"
        assert a._map_severity("green") == "low"

    def test_case_insensitive(self):
        a = _adapter()
        assert a._map_severity("RED") == "critical"

    def test_unknown_passes_through(self):
        a = _adapter()
        assert a._map_severity("purple") == "purple"

    def test_none(self):
        a = _adapter()
        assert a._map_severity(None) is None
        assert a._map_severity("") == ""


class TestResolveTlpColor:
    def test_returns_lowercased_known_color(self):
        a = _adapter(tlp_color="AMBER")
        assert a._resolve_tlp_color("incident") == "amber"

    def test_default_per_sdo_when_unknown(self):
        a = _adapter(tlp_color=None)
        # DEFAULT_TLP_BY_SDO["malware"] = "amber+strict".
        assert a._resolve_tlp_color("malware") == "amber+strict"

    def test_default_fallback_amber(self):
        a = _adapter(tlp_color=None)
        # Unknown SDO type with no default → "amber".
        assert a._resolve_tlp_color("unknown-sdo-type") == "amber"


class TestTlpMarkingFor:
    def test_returns_stix2_marking(self):
        a = _adapter(tlp_color="amber")
        m = a._tlp_marking_for("domain-name")
        assert getattr(m, "type", None) == "marking-definition"


class TestSetGlobalLabel:
    def test_nation_state_for_apt(self):
        a = _adapter(collection="apt/threat")
        assert a.ta_global_label == "nation_state"

    def test_nation_state_for_apt_actor(self):
        a = _adapter(collection="apt/threat_actor")
        assert a.ta_global_label == "nation_state"

    def test_cybercriminal_for_hi(self):
        a = _adapter(collection="hi/threat")
        assert a.ta_global_label == "cybercriminal"

    def test_cybercriminal_for_open_threats(self):
        a = _adapter(collection="hi/open_threats")
        assert a.ta_global_label == "cybercriminal"

    def test_no_label_for_other_collections(self):
        a = _adapter(collection="malware/cnc")
        assert a.ta_global_label is None


# --- Label format helpers ---------------------------------------------------


class TestFormatLabels:
    def test_threat_actor_label_returns_bare_name(self):
        a = _adapter()
        assert a._format_threat_actor_label("FIN-X") == "FIN-X"

    def test_threat_actor_label_strips(self):
        a = _adapter()
        assert a._format_threat_actor_label("  FIN-X  ") == "FIN-X"

    def test_threat_actor_label_empty_or_blank_returns_none(self):
        a = _adapter()
        assert a._format_threat_actor_label(None) is None
        assert a._format_threat_actor_label("") is None
        assert a._format_threat_actor_label("   ") is None

    def test_malware_label_returns_bare_name(self):
        a = _adapter()
        assert a._format_malware_label("MalwareAlpha") == "MalwareAlpha"
        assert a._format_malware_label(None) is None


# --- Text preview ------------------------------------------------------------


class TestGetTextPreview:
    def test_default_truncates_long_text(self):
        a = _adapter()
        text = "x" * 5000
        out = a._get_text_preview("compromised_access", text)
        # default_max_len = 2000.
        assert out.endswith("...")
        assert len(out) == 2003  # 2000 + "..."

    def test_short_text_unchanged(self):
        a = _adapter()
        assert a._get_text_preview("any", "short") == "short"


# --- Log helper --------------------------------------------------------------


class TestLogSkipped:
    def test_emits_info_log(self):
        a = _adapter(collection="malware/cnc")
        a._log_skipped("domain", "bad-value")
        # Helper logger gets at least one info call (kind, value, default reason).
        calls = a.helper.connector_logger.info.call_args_list
        assert any("malware/cnc" in str(c) for c in calls)
        assert any("domain" in str(c) for c in calls)
        assert any("bad-value" in str(c) for c in calls)

    def test_custom_reason(self):
        a = _adapter()
        a._log_skipped("url", "x", reason="length>1024")
        call_args = str(a.helper.connector_logger.info.call_args_list[-1])
        assert "length>1024" in call_args


# --- ISO date parsing -------------------------------------------------------


class TestParseIsoUtc:
    def test_iso_z(self):
        a = _adapter()
        out = a._parse_iso_utc("2024-01-01T00:00:00Z")
        assert out == datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_iso_with_offset(self):
        a = _adapter()
        out = a._parse_iso_utc("2024-01-01T01:00:00+01:00")
        # Same UTC instant as 00:00:00Z.
        assert out == datetime(2024, 1, 1, tzinfo=timezone.utc)

    def test_naive_iso_assumed_utc(self):
        a = _adapter()
        out = a._parse_iso_utc("2024-01-01T00:00:00")
        assert out is not None
        assert out.tzinfo is not None

    def test_invalid_returns_none(self):
        a = _adapter()
        assert a._parse_iso_utc("not-a-date") is None
        assert a._parse_iso_utc(None) is None
        assert a._parse_iso_utc("") is None


# --- TTL helpers ------------------------------------------------------------


class TestResolveTtlDays:
    """Signature: ``_resolve_ttl_days(collection_key, json_date_obj=...)`` —
    consults the per-collection TTL config first, then the event's ``ttl``.

    Use an unknown collection-key so the real ``.env``-loaded config can't
    short-circuit the test (``apt_threat`` ships with TTL=1460 in the real
    config, masking the json_date_obj path).
    """

    UNKNOWN = "no_such_collection_xyz"

    def test_uses_event_ttl_when_config_empty(self):
        a = _adapter()
        out = a._resolve_ttl_days(self.UNKNOWN, {"ttl": 42})
        assert out == 42

    def test_falls_back_to_default(self):
        a = _adapter()
        # Neither config nor json_date_obj provides ttl → DEFAULT_TTL_DAYS = 365.
        out = a._resolve_ttl_days(self.UNKNOWN, {})
        assert out == 365

    def test_invalid_value_falls_back(self):
        a = _adapter()
        out = a._resolve_ttl_days(self.UNKNOWN, {"ttl": "not-an-int"})
        assert out == 365

    def test_non_positive_value_ignored(self):
        a = _adapter()
        # Zero and negatives are ignored; falls through to default.
        out = a._resolve_ttl_days(self.UNKNOWN, {"ttl": -5})
        assert out == 365


# --- _resolve_entity_labels --------------------------------------------------


class TestResolveEntityLabels:
    def test_collection_label_only(self):
        a = _adapter(collection="apt/threat")
        labels, _ = a._resolve_entity_labels(collection_label="apt/threat")
        # The collection display label is the prefixed "collection:..." value.
        assert any(lbl.startswith("collection:") for lbl in labels)

    def test_malware_names_added(self):
        a = _adapter(collection="malware/cnc")
        labels, _ = a._resolve_entity_labels(
            collection_label="malware/cnc",
            malware_names=["MalwareAlpha", "MalwareGamma"],
        )
        # Bare malware names appear as labels (no prefix).
        assert "MalwareAlpha" in labels
        assert "MalwareGamma" in labels

    def test_threat_actor_names_added(self):
        a = _adapter(collection="malware/cnc")
        labels, _ = a._resolve_entity_labels(
            collection_label="malware/cnc",
            threat_actor_names=["FIN-X"],
        )
        assert "FIN-X" in labels

    def test_source_types_added_for_account_group(self):
        a = _adapter(collection="compromised/account_group")
        labels, _ = a._resolve_entity_labels(
            collection_label="compromised/account_group",
            source_types=["leak", "combolist"],
        )
        # Source-type values land as bare labels.
        assert "leak" in labels
        assert "combolist" in labels
