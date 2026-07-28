from __future__ import annotations

from connector.settings import (
    COLLECTION_DISPLAY_LABEL,
    DESC_BR_RE,
    DESC_CLOSE_LI_RE,
    DESC_CLOSE_P_RE,
    DESC_HSPACE_RE,
    DESC_OPEN_LI_RE,
    DESC_OPEN_P_RE,
    DESC_PARA_RE,
    DESC_TAG_RE,
    DOMAIN_RE,
    EMAIL_RE,
    ConfigConnector,
)

# --- Pure-function helpers ---------------------------------------------------


class TestToBool:
    def test_none_returns_default_false(self):
        assert ConfigConnector._to_bool(None) is False

    def test_none_returns_explicit_default(self):
        assert ConfigConnector._to_bool(None, default=True) is True

    def test_python_true(self):
        assert ConfigConnector._to_bool(True) is True

    def test_python_false(self):
        assert ConfigConnector._to_bool(False) is False

    def test_string_true_lowercase(self):
        assert ConfigConnector._to_bool("true") is True

    def test_string_true_uppercase(self):
        assert ConfigConnector._to_bool("TRUE") is True

    def test_string_true_mixedcase(self):
        assert ConfigConnector._to_bool("True") is True

    def test_string_one(self):
        assert ConfigConnector._to_bool("1") is True

    def test_string_yes(self):
        assert ConfigConnector._to_bool("yes") is True
        assert ConfigConnector._to_bool("YES") is True

    def test_string_false_returns_false(self):
        assert ConfigConnector._to_bool("false") is False

    def test_unknown_string_returns_false(self):
        assert ConfigConnector._to_bool("maybe") is False
        assert ConfigConnector._to_bool("nope") is False

    def test_empty_string_returns_false(self):
        assert ConfigConnector._to_bool("") is False

    def test_int_zero_returns_false(self):
        # ``str(0).lower()`` -> "0", which is not in the truthy set.
        assert ConfigConnector._to_bool(0) is False

    def test_int_one_returns_true(self):
        # ``str(1).lower()`` -> "1", which is in the truthy set.
        assert ConfigConnector._to_bool(1) is True


class TestToInt:
    def test_none_returns_zero(self):
        assert ConfigConnector._to_int(None) == 0

    def test_none_returns_default(self):
        assert ConfigConnector._to_int(None, default=42) == 42

    def test_int_passthrough(self):
        assert ConfigConnector._to_int(7) == 7

    def test_numeric_string(self):
        assert ConfigConnector._to_int("123") == 123

    def test_negative_string(self):
        assert ConfigConnector._to_int("-5") == -5

    def test_non_numeric_string_falls_back(self):
        assert ConfigConnector._to_int("not-a-number", default=100) == 100

    def test_empty_string_falls_back(self):
        assert ConfigConnector._to_int("", default=99) == 99

    def test_float_string_falls_back(self):
        # ``int("1.5")`` raises, so the default branch fires.
        assert ConfigConnector._to_int("1.5", default=7) == 7


# --- _converting_keys_to_environment_keys ------------------------------------
#
# Instance method but reads no ``self`` state, so we call it as if static via
# the ``ConfigConnector.__dict__`` lookup to dodge the heavy ``__init__``.


def _convert(key):
    inst = ConfigConnector.__new__(ConfigConnector)
    return inst._converting_keys_to_environment_keys(key)


class TestConvertingKeysToEnvironmentKeys:
    def test_empty_returns_none(self):
        assert _convert([]) is None
        assert _convert(None) is None

    def test_non_list_returns_none(self):
        assert _convert("opencti") is None
        assert _convert(42) is None

    def test_opencti_two_level(self):
        # ["opencti", "url"] -> "OPENCTI_URL".
        assert _convert(["opencti", "url"]) == "OPENCTI_URL"

    def test_connector_two_level(self):
        assert _convert(["connector", "id"]) == "CONNECTOR_ID"

    def test_ti_api_two_level_double_underscore(self):
        # TI_API uses ``__`` joiner, not ``_``.
        assert _convert(["ti_api", "url"]) == "TI_API__URL"

    def test_ti_api_extra_settings(self):
        out = _convert(["ti_api", "extra_settings", "ignore_non_malware_ddos"])
        assert out == "TI_API__EXTRA_SETTINGS__IGNORE_NON_MALWARE_DDOS"

    def test_ti_api_collections_slug_converted(self):
        # The "/" in the collection slug becomes "_" in the env var name.
        out = _convert(["ti_api", "collections", "apt/threat", "enable"])
        assert out == "TI_API__COLLECTIONS__APT_THREAT__ENABLE"

    def test_ti_api_collections_only(self):
        # No sub-keys → only the collections section name.
        out = _convert(["ti_api", "collections"])
        assert out == "TI_API__COLLECTIONS"

    def test_other_section_underscore_joined(self):
        # Anything outside the three known prefixes uses single ``_``.
        assert _convert(["misc", "foo", "bar"]) == "MISC_FOO_BAR"

    def test_hyphens_normalised_to_underscores(self):
        assert _convert(["my-section", "my-key"]) == "MY_SECTION_MY_KEY"


# --- _extract_config_keys ----------------------------------------------------
#
# Instance method but reads no ``self`` state — pass ``ConfigConnector`` as the
# stand-in instance.


def _extract(data):
    # Bypass __init__ (which does .env / mapping.json I/O) but get a real
    # instance so the recursive ``self._extract_config_keys(...)`` call
    # inside the method dispatches to a properly-bound method (passing
    # the CLASS as self would treat the recursive ``value`` arg as self).
    inst = ConfigConnector.__new__(ConfigConnector)
    return inst._extract_config_keys(data)


class TestExtractConfigKeys:
    def test_empty_dict(self):
        assert _extract({}) == []

    def test_non_dict(self):
        assert _extract("scalar") == []
        assert _extract(None) == []
        assert _extract([1, 2, 3]) == []

    def test_flat_dict(self):
        out = _extract({"a": 1, "b": 2})
        assert sorted(out) == [["a"], ["b"]]

    def test_nested_one_level(self):
        out = _extract({"x": {"y": 1}})
        assert out == [["x", "y"]]

    def test_nested_deep(self):
        out = _extract({"x": {"y": {"z": 1}}})
        assert out == [["x", "y", "z"]]

    def test_mixed_leaves_and_branches(self):
        out = _extract({"a": 1, "b": {"c": 2, "d": 3}})
        # Three leaves total: ["a"], ["b","c"], ["b","d"].
        assert len(out) == 3


# --- COLLECTION_DISPLAY_LABEL / COLLECTION_MAP -------------------------------


class TestCollectionMaps:
    def test_display_label_has_31_entries(self):
        assert len(COLLECTION_DISPLAY_LABEL) == 31

    def test_every_display_label_has_collection_prefix(self):
        for slug, label in COLLECTION_DISPLAY_LABEL.items():
            assert label.startswith(
                "collection:"
            ), f"{slug} -> {label!r}: must start with 'collection:'"

    def test_collection_map_matches_display_label(self):
        # Both enumerate the same 31 collection slugs.
        slugs_from_map = set(ConfigConnector.COLLECTION_MAP.values())
        slugs_from_display = set(COLLECTION_DISPLAY_LABEL.keys())
        assert slugs_from_map == slugs_from_display

    def test_collection_map_keys_use_underscore_only(self):
        for env_key in ConfigConnector.COLLECTION_MAP.keys():
            assert "/" not in env_key
            assert env_key == env_key.lower()

    def test_collection_map_values_use_slash(self):
        # Slashes are the canonical Group-IB collection-slug form.
        for slug in ConfigConnector.COLLECTION_MAP.values():
            assert "/" in slug

    def test_ioc_common_removed(self):
        # ioc/common was retired in favour of ioc/primary; both maps must
        # never re-introduce it.
        assert "ioc/common" not in COLLECTION_DISPLAY_LABEL
        assert "ioc/common" not in ConfigConnector.COLLECTION_MAP.values()
        assert "ioc_common" not in ConfigConnector.COLLECTION_MAP

    def test_ioc_primary_present(self):
        assert "ioc/primary" in COLLECTION_DISPLAY_LABEL
        assert "ioc/primary" in ConfigConnector.COLLECTION_MAP.values()

    def test_no_duplicate_labels(self):
        labels = list(COLLECTION_DISPLAY_LABEL.values())
        assert len(labels) == len(set(labels))


# --- Regex constants ---------------------------------------------------------


class TestEmailRegex:
    def test_simple_email(self):
        assert EMAIL_RE.match("alice@example.com") is not None

    def test_plus_addressing(self):
        assert EMAIL_RE.match("alice+test@example.com") is not None

    def test_dotted_local_part(self):
        assert EMAIL_RE.match("alice.smith@example.com") is not None

    def test_subdomain(self):
        assert EMAIL_RE.match("u@sub.example.com") is not None

    def test_hyphenated_domain_label(self):
        # EMAIL_RE has no punycode-specific rule; an ``xn--`` label is just
        # an ordinary hyphen-containing label and is accepted as such.
        assert EMAIL_RE.match("u@xn--example.com") is not None

    def test_rejects_no_at(self):
        assert EMAIL_RE.match("no-at-sign") is None

    def test_rejects_trailing_dot(self):
        assert EMAIL_RE.match("u@example.") is None

    def test_rejects_leading_dot_in_domain(self):
        assert EMAIL_RE.match("u@.example.com") is None

    def test_rejects_space(self):
        assert EMAIL_RE.match("a b@example.com") is None

    def test_rejects_double_at(self):
        assert EMAIL_RE.match("u@@example.com") is None

    def test_accepts_alphanumeric_labels(self):
        # The regex permits any ASCII alphanumeric label (the OpenCTI
        # observable-format check that rejects numeric-only TLDs happens
        # server-side in addition to this client-side regex).
        assert EMAIL_RE.match("u@host42.example.com") is not None


class TestDomainRegex:
    def test_simple_domain(self):
        assert DOMAIN_RE.match("example.com") is not None

    def test_subdomain(self):
        assert DOMAIN_RE.match("a.b.c.example.com") is not None

    def test_punycode_tld(self):
        # The punycode ``xn--`` alternative applies to the FINAL label, so
        # use a punycode TLD (this fails if the xn-- branch is removed).
        assert DOMAIN_RE.match("example.xn--p1ai") is not None

    def test_hyphen_in_label(self):
        assert DOMAIN_RE.match("my-host.example.com") is not None

    def test_rejects_leading_hyphen(self):
        assert DOMAIN_RE.match("-bad.invalid") is None

    def test_rejects_trailing_hyphen(self):
        assert DOMAIN_RE.match("bad-.com") is None

    def test_rejects_underscore(self):
        assert DOMAIN_RE.match("a_b.invalid") is None

    def test_rejects_numeric_tld(self):
        # An IPv4 must not parse as a domain — adapters re-emit it as IP.
        assert DOMAIN_RE.match("192.0.2.1") is None

    def test_rejects_single_label(self):
        assert DOMAIN_RE.match("localhost") is None

    def test_rejects_trailing_dot(self):
        # Trailing-dot canonical FQDN isn't accepted by the regex (consistent
        # with how OpenCTI rejects observables with trailing dots).
        assert DOMAIN_RE.match("example.com.") is None


class TestDescRegexes:
    def test_br_matches(self):
        assert DESC_BR_RE.search("hello<br/>world") is not None
        assert DESC_BR_RE.search("a<br>b") is not None
        assert DESC_BR_RE.search("a<BR />b") is not None

    def test_p_close_matches(self):
        assert DESC_CLOSE_P_RE.search("</p>") is not None
        assert DESC_CLOSE_P_RE.search("</P >") is not None

    def test_p_open_matches_with_attrs(self):
        assert DESC_OPEN_P_RE.search('<p class="x">') is not None
        assert DESC_OPEN_P_RE.search("<p>") is not None

    def test_li_close_matches(self):
        assert DESC_CLOSE_LI_RE.search("</li>") is not None

    def test_li_open_matches(self):
        assert DESC_OPEN_LI_RE.search('<li class="x">') is not None

    def test_generic_tag_matches(self):
        assert DESC_TAG_RE.search("<unknown>") is not None

    def test_hspace_matches_runs(self):
        assert DESC_HSPACE_RE.search("a    b") is not None
        assert DESC_HSPACE_RE.search("a\t\tb") is not None
        assert DESC_HSPACE_RE.search("a\xa0b") is not None  # nbsp
        # Single newline / vertical whitespace is NOT in the class.
        assert DESC_HSPACE_RE.search("a\nb") is None

    def test_para_split_matches_blank_lines(self):
        assert DESC_PARA_RE.search("a\n\nb") is not None
        assert DESC_PARA_RE.search("a\n\n\nb") is not None
        # Single newline is not a paragraph break.
        assert DESC_PARA_RE.search("a\nb") is None
