from __future__ import annotations

from pipeline.collection_dispatch import (
    IOC_OBSERVABLE_FLAGS,
    SPECIAL_COLLECTIONS,
    ObservableIocFlags,
    SpecialCollection,
    get_observable_ioc_flags,
    resolve_special_tlp,
)

# --- ObservableIocFlags ------------------------------------------------------


class TestObservableIocFlags:
    def test_defaults_all_false(self):
        flags = ObservableIocFlags()
        assert flags.file is False
        assert flags.domain is False
        assert flags.url is False
        assert flags.ip is False
        assert flags.yara is False
        assert flags.suricata is False
        assert flags.email is False

    def test_custom_values(self):
        flags = ObservableIocFlags(file=True, domain=True, ip=True)
        assert flags.file is True
        assert flags.domain is True
        assert flags.ip is True
        assert flags.url is False
        assert flags.yara is False

    def test_frozen(self):
        flags = ObservableIocFlags()
        try:
            flags.file = True
        except Exception as e:
            assert (
                "frozen" in str(e).lower() or "FrozenInstanceError" in type(e).__name__
            )
        else:  # pragma: no cover
            raise AssertionError("ObservableIocFlags should be frozen")


# --- IOC_OBSERVABLE_FLAGS map + lookup ---------------------------------------


class TestIocFlagsMap:
    def test_default_flow_threat_reports_are_ioc(self):
        # apt/threat + hi/threat IOCs come from indicators.params.
        for c in (
            "apt/threat",
            "hi/threat",
            "apt/threat_actor",
            "hi/threat_actor",
            "malware/malware",
        ):
            flags = IOC_OBSERVABLE_FLAGS[c]
            assert flags.file and flags.domain and flags.url and flags.ip, c

    def test_yara_suricata_collections(self):
        for c in ("malware/signature", "malware/yara"):
            flags = IOC_OBSERVABLE_FLAGS[c]
            assert flags.yara and flags.suricata, c
            # YARA/Suricata families don't carry observable IOCs.
            assert not flags.file and not flags.domain

    def test_suspicious_ip_all_non_ioc(self):
        for c in (
            "suspicious_ip/open_proxy",
            "suspicious_ip/scanner",
            "suspicious_ip/socks_proxy",
            "suspicious_ip/tor_node",
            "suspicious_ip/vpn",
        ):
            flags = IOC_OBSERVABLE_FLAGS[c]
            # Non-IOC presets: nothing flagged.
            assert flags.file is False
            assert flags.domain is False
            assert flags.url is False
            assert flags.ip is False
            assert flags.email is False

    def test_get_returns_default_for_unknown(self):
        # Special-flow collections aren't in IOC_OBSERVABLE_FLAGS — they
        # fall back to the empty default.
        flags = get_observable_ioc_flags("compromised/account_group")
        assert flags == ObservableIocFlags()

    def test_get_returns_mapped_for_known(self):
        assert get_observable_ioc_flags("apt/threat").file is True

    def test_get_for_truly_unknown_slug(self):
        flags = get_observable_ioc_flags("nope/never")
        assert flags == ObservableIocFlags()


# --- SpecialCollection -------------------------------------------------------


class TestSpecialCollection:
    def test_required_method_name(self):
        spec = SpecialCollection("generate_ioc_primary", is_ioc=True)
        assert spec.method_name == "generate_ioc_primary"
        assert spec.is_ioc is True
        assert spec.tlp_strict is None
        assert spec.tlp_fallback is None

    def test_optional_tlp_fields(self):
        spec = SpecialCollection(
            "x", is_ioc=False, tlp_strict="red", tlp_fallback="amber"
        )
        assert spec.tlp_strict == "red"
        assert spec.tlp_fallback == "amber"

    def test_frozen(self):
        spec = SpecialCollection("x", is_ioc=False)
        try:
            spec.is_ioc = True
        except Exception as e:
            assert (
                "frozen" in str(e).lower() or "FrozenInstanceError" in type(e).__name__
            )
        else:  # pragma: no cover
            raise AssertionError("SpecialCollection should be frozen")


# --- SPECIAL_COLLECTIONS dispatch table --------------------------------------


class TestSpecialCollectionsTable:
    def test_method_names_follow_naming_convention(self):
        # Every dispatch entry must point at ``generate_<collection-name>``.
        for slug, spec in SPECIAL_COLLECTIONS.items():
            assert spec.method_name.startswith("generate_"), slug

    def test_ioc_primary_is_strict_amber(self):
        spec = SPECIAL_COLLECTIONS["ioc/primary"]
        assert spec.is_ioc is True
        assert spec.tlp_strict == "amber"
        assert spec.tlp_fallback is None

    def test_compromised_account_group_is_strict_red(self):
        spec = SPECIAL_COLLECTIONS["compromised/account_group"]
        assert spec.is_ioc is False
        assert spec.tlp_strict == "red"

    def test_chat_collections_fallback_red(self):
        # Chat-platform messages carry sensitive PII; default to RED if the
        # event omits a TLP marking.
        for slug in ("compromised/discord", "compromised/messenger"):
            spec = SPECIAL_COLLECTIONS[slug]
            assert spec.tlp_fallback == "red", slug
            assert spec.tlp_strict is None, slug

    def test_attacks_phishing_kit_and_group_emit_iocs(self):
        for slug in ("attacks/phishing_group", "attacks/phishing_kit"):
            assert SPECIAL_COLLECTIONS[slug].is_ioc is True, slug

    def test_no_ioc_common_entry(self):
        # ioc/common was retired; only ioc/primary survives in the table.
        assert "ioc/common" not in SPECIAL_COLLECTIONS

    def test_method_names_are_unique(self):
        names = [spec.method_name for spec in SPECIAL_COLLECTIONS.values()]
        assert len(names) == len(set(names))

    def test_table_size(self):
        # 31 collections total; 19 of them go through special dispatch
        # handlers. Lock the count so accidental additions/removals show
        # up in review.
        assert len(SPECIAL_COLLECTIONS) == 19

    def test_all_special_method_names_match_slug(self):
        for slug, spec in SPECIAL_COLLECTIONS.items():
            # ``compromised/account_group`` -> ``generate_compromised_account_group``
            expected = "generate_" + slug.replace("/", "_")
            assert spec.method_name == expected, (slug, spec.method_name)


# --- resolve_special_tlp -----------------------------------------------------


class TestResolveSpecialTlp:
    def test_strict_always_wins(self):
        spec = SpecialCollection("x", is_ioc=False, tlp_strict="red")
        assert resolve_special_tlp(spec, "amber") == "red"
        assert resolve_special_tlp(spec, None) == "red"

    def test_fallback_used_when_event_has_none(self):
        spec = SpecialCollection("x", is_ioc=False, tlp_fallback="amber")
        assert resolve_special_tlp(spec, None) == "amber"

    def test_fallback_overridden_by_event_tlp(self):
        # fallback only fires when the event omits a TLP.
        spec = SpecialCollection("x", is_ioc=False, tlp_fallback="amber")
        assert resolve_special_tlp(spec, "green") == "green"
        assert resolve_special_tlp(spec, "red") == "red"

    def test_neither_set_returns_event_tlp(self):
        spec = SpecialCollection("x", is_ioc=False)
        assert resolve_special_tlp(spec, "amber") == "amber"
        assert resolve_special_tlp(spec, None) is None

    def test_strict_beats_fallback(self):
        # Strict and fallback together would be a config bug, but if both
        # are present the strict value wins.
        spec = SpecialCollection(
            "x", is_ioc=False, tlp_strict="red", tlp_fallback="green"
        )
        assert resolve_special_tlp(spec, "amber") == "red"

    def test_empty_string_event_tlp_treated_as_missing(self):
        # ``"" or fallback`` -> fallback. Confirms truthiness semantics.
        spec = SpecialCollection("x", is_ioc=False, tlp_fallback="amber")
        assert resolve_special_tlp(spec, "") == "amber"
