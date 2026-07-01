from __future__ import annotations

from support.incident_note_markdown import (
    _safe_str_trunc,
    markdown_attacks_ddos,
    markdown_attacks_deface,
    markdown_attacks_phishing_group,
    markdown_attacks_phishing_kit,
    markdown_compromised_access,
    markdown_compromised_account_group,
    markdown_compromised_bank_card_group,
    markdown_compromised_masked_card,
    markdown_compromised_spd,
    markdown_darkweb_forums,
    markdown_hi_open_threats,
    markdown_ioc_note,
    markdown_malware,
    markdown_malware_cnc,
    markdown_malware_config,
    markdown_osi_git_repository,
    markdown_osi_public_leak,
    markdown_osi_vulnerability,
    markdown_threat_actor,
    markdown_threat_report,
    matches_struct_to_markdown_lines,
)

# --- helpers -----------------------------------------------------------------


def _flatten_cell(v):
    """Same shape as ``AdapterCoreMixin._flatten_cell`` — the markdown
    builders take it as a callable parameter."""
    if v is None:
        return ""
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v)


# --- matches_struct_to_markdown_lines ----------------------------------------


class TestMatchesStructToMarkdownLines:
    def test_none_returns_empty(self):
        assert matches_struct_to_markdown_lines(None) == []

    def test_empty_dict_returns_empty(self):
        assert matches_struct_to_markdown_lines({}) == []

    def test_flat_dict_one_level(self):
        out = matches_struct_to_markdown_lines({"key": "value"})
        # Header + separator + 1 row.
        assert len(out) == 3
        assert out[0] == "| Key 1 | Values |"
        assert out[1] == "| --- | --- |"
        assert out[2] == "| key | value |"

    def test_nested_dict_extends_columns(self):
        out = matches_struct_to_markdown_lines({"a": {"b": "v"}})
        # Two-key depth → 3 columns total (Key 1, Key 2, Values).
        assert "Key 1" in out[0] and "Key 2" in out[0]
        assert "| a | b | v |" in out

    def test_list_value_joins_with_comma(self):
        out = matches_struct_to_markdown_lines({"k": ["v1", "v2", "v3"]})
        assert "v1, v2, v3" in out[-1]

    def test_empty_list_renders_blank(self):
        out = matches_struct_to_markdown_lines({"k": []})
        # Row exists, value-cell is empty.
        assert out[-1].rstrip().endswith("|  |")

    def test_pipe_escaped(self):
        out = matches_struct_to_markdown_lines({"k": "a|b"})
        assert "a\\|b" in out[-1]

    def test_newline_in_value_becomes_space(self):
        out = matches_struct_to_markdown_lines({"k": "line1\nline2"})
        assert "line1 line2" in out[-1]

    def test_long_value_truncated(self):
        out = matches_struct_to_markdown_lines({"k": "x" * 700}, values_max_len=50)
        # Last row's value cell ends with "..." after truncation.
        assert "..." in out[-1]
        # The total inserted length doesn't exceed values_max_len.
        cell = out[-1].split("|")[-2].strip()
        assert len(cell) <= 50

    def test_padding_for_shallower_branches(self):
        # Mixed-depth structure: some leaves at depth 1, others at depth 2.
        # The shallower leaf gets padded with empty key cells so column
        # counts match.
        out = matches_struct_to_markdown_lines({"shallow": "v1", "deep": {"k": "v2"}})
        # Two-level depth → 3 columns ("Key 1", "Key 2", "Values").
        # Each row format is "| c1 | c2 | c3 |" → 4 pipes.
        shallow_row = [r for r in out if "shallow" in r][0]
        assert shallow_row.count("|") == 4
        # And the shallower row carries an empty Key 2 cell (padding):
        # "| shallow |  | v1 |" — note the double space between pipes 2-3.
        assert "shallow |  |" in shallow_row


# --- _safe_str_trunc ---------------------------------------------------------


class TestSafeStrTrunc:
    def test_none(self):
        assert _safe_str_trunc(None, 10) == ""

    def test_short_unchanged(self):
        assert _safe_str_trunc("hi", 10) == "hi"

    def test_strips_whitespace(self):
        assert _safe_str_trunc("  hi  ", 10) == "hi"

    def test_truncated_with_ellipsis(self):
        out = _safe_str_trunc("x" * 50, 10)
        assert out == "x" * 10 + "..."

    def test_int_coerced(self):
        assert _safe_str_trunc(12345, 10) == "12345"


# --- markdown_compromised_account_group --------------------------------------


class TestCompromisedAccountGroup:
    def test_minimal(self):
        out = markdown_compromised_account_group(
            login=None,
            password=None,
            include_passwords=False,
            service={},
            parsed_login={},
            date_first_seen=None,
            date_last_seen=None,
            date_first_compromised=None,
            date_last_compromised=None,
            events_table=[],
        )
        assert "## Account" in out
        assert "<unknown>" in out  # login fallback
        assert "<redacted>" in out  # password redacted when include_passwords=False

    def test_password_revealed_when_flag_on(self):
        out = markdown_compromised_account_group(
            login="alice@example.com",
            password="hunter2",
            include_passwords=True,
            service={"url": "https://example.com", "domain": "example.com"},
            parsed_login={},
            date_first_seen="2024-01-01",
            date_last_seen="2024-02-01",
            date_first_compromised="2024-01-15",
            date_last_compromised="2024-02-15",
            events_table=[],
        )
        assert "hunter2" in out
        assert "alice@example.com" in out

    def test_password_redacted_when_present_but_flag_off(self):
        out = markdown_compromised_account_group(
            login="x",
            password="hunter2",
            include_passwords=False,
            service={},
            parsed_login={},
            date_first_seen=None,
            date_last_seen=None,
            date_first_compromised=None,
            date_last_compromised=None,
            events_table=[],
        )
        assert "hunter2" not in out
        assert "<redacted>" in out

    def test_parsed_login_section_renders_when_set(self):
        out = markdown_compromised_account_group(
            login="x",
            password=None,
            include_passwords=False,
            service={},
            parsed_login={"domain": "corp.local", "ip": "10.99.0.1"},
            date_first_seen=None,
            date_last_seen=None,
            date_first_compromised=None,
            date_last_compromised=None,
            events_table=[],
        )
        assert "## Parsed login" in out
        assert "corp.local" in out
        assert "10.99.0.1" in out

    def test_events_table_renders(self):
        events = [
            {
                "dateDetected": "2024-01-01",
                "dateCompromised": "2024-01-02",
                "events_ipv4_ip": "192.0.2.1",
                "malware": "MalwareGamma",
                "threatActor": "broker-x",
                "countryCode": "US",
                "region": "California",
                "asn": "AS-1234",
            },
            "not a dict — must be skipped",
        ]
        out = markdown_compromised_account_group(
            login="x",
            password=None,
            include_passwords=False,
            service={},
            parsed_login={},
            date_first_seen=None,
            date_last_seen=None,
            date_first_compromised=None,
            date_last_compromised=None,
            events_table=events,
        )
        assert "## Events" in out
        assert "MalwareGamma" in out
        assert "AS-1234" in out


# --- markdown_compromised_bank_card_group ------------------------------------


class TestCompromisedBankCardGroup:
    def _base_kwargs(self):
        return dict(
            item_id="card-1",
            card_number="1234-5678-...",
            card_type=None,
            card_category=None,
            card_system=None,
            card_bin=None,
            card_issuer=None,
            card_issuer_country=None,
            date_first_seen=None,
            date_last_seen=None,
            date_first_compromised=None,
            date_last_compromised=None,
            raw_ta_list=[],
            raw_source_list=[],
            malware_names=[],
            events_table=[],
            flatten_cell=_flatten_cell,
        )

    def test_minimal(self):
        out = markdown_compromised_bank_card_group(**self._base_kwargs())
        assert "## Card Info" in out
        assert "card-1" in out

    def test_full(self):
        kw = self._base_kwargs()
        kw.update(
            card_bin=[123456, 987654],
            card_issuer="Bank X",
            card_issuer_country="US",
            raw_ta_list=[
                {"name": "FIN-X", "id": "ta-1"},
                "skip-non-dict",
            ],
            raw_source_list=[{"type": "shop", "id": "s-1", "idType": "uuid"}],
            malware_names=["MalwareGamma"],
            events_table=[
                {
                    "dateDetected": "d1",
                    "dateCompromised": "d2",
                    "malware_name": "MalwareGamma",
                    "threatActor_name": "FIN-X",
                    "cnc": "example.com",
                    "cnc_ipv4_ip": "192.0.2.1",
                    "client_ipv4_ip": "192.0.2.3",
                    "price": 9.99,
                    "source_type": "leak",
                },
                None,
            ],
        )
        out = markdown_compromised_bank_card_group(**kw)
        assert "## Threat actors" in out
        assert "FIN-X" in out
        assert "## Sources" in out
        assert "uuid" in out
        assert "## Malware" in out
        assert "MalwareGamma" in out
        assert "## Compromise events" in out
        assert "192.0.2.3" in out


# --- markdown_compromised_access ---------------------------------------------


class TestCompromisedAccess:
    def test_minimal(self):
        out = markdown_compromised_access(
            access_id="acc-1",
            payload={},
            target={},
            cnc={},
            malware_obj={},
            source_info={},
            price={},
            raw_preview=None,
            raw_use_full=False,
            raw_max_len=None,
        )
        assert "## Compromised access" in out
        assert "acc-1" in out

    def test_full_with_preview(self):
        out = markdown_compromised_access(
            access_id="acc-1",
            payload={"type": "shop", "description": "long body"},
            target={"host": "h", "domain": "d", "country": "US"},
            cnc={"cnc": "c2.example.com", "port": 443},
            malware_obj={"name": "MalwareGamma", "id": "m-1"},
            source_info={"name": "shop-x", "seller": "broker"},
            price={"value": 100, "currency": "USD"},
            raw_preview="raw data content",
            raw_use_full=False,
            raw_max_len=10,
        )
        assert "Raw data (preview)" in out
        # ``_safe_str_trunc("raw data content", 10)`` → "raw data c..."
        assert "raw data c..." in out

    def test_full_data_renders_untruncated(self):
        out = markdown_compromised_access(
            access_id="x",
            payload={},
            target={},
            cnc={},
            malware_obj={},
            source_info={},
            price={},
            raw_preview="full body" * 100,
            raw_use_full=True,
            raw_max_len=10,  # ignored when use_full=True
        )
        assert "Raw data" in out
        assert "full body" * 100 in out


# --- markdown_compromised_spd ------------------------------------------------


class TestCompromisedSpd:
    def test_minimal(self):
        out = markdown_compromised_spd(
            spd_id="spd-1",
            payload={},
            value_obj={},
            ptype_str="phone",
            value_str="+1-555",
            events_list=[],
            malware_list=[],
            ta_list=[],
        )
        assert "## Suspicious payment details" in out
        assert "+1-555" in out

    def test_full(self):
        out = markdown_compromised_spd(
            spd_id="spd-1",
            payload={
                "type": "phone",
                "service_type": "casino",
                "ownerName": "John",
                "illegalScore": 9,
                "country": ["US", "GB"],
                "tags": ["Casino", "Phone"],
                "sources": [
                    {"name": "leak-site", "type": "darkweb"},
                    "skip-non-dict",
                ],
            },
            value_obj={
                "email": "a@example.com",
                "bankCard": "4111",
                "iban": "GB...",
            },
            ptype_str="phone",
            value_str="+1-555",
            events_list=[
                {
                    "compromisedAt": "c1",
                    "detectedAt": "d1",
                    "source_name": "x",
                    "source_type": "y",
                    "tags": ["a", "b"],
                    "illegalScore": 5,
                },
                None,
            ],
            # The source iterates dict-style items only — a bare string in
            # ``malware_list`` / ``ta_list`` would trigger ``.get("name")``
            # on a str (no such method). Feed dicts/None to match the
            # ingestion contract (mapping.json normalises lists to dicts).
            malware_list=[{"name": "MalwareGamma"}, None],
            ta_list=[{"name": "FIN-X"}],
        )
        assert "## Events" in out
        assert "## Sources" in out
        assert "leak-site" in out
        assert "## Malware" in out
        assert "MalwareGamma" in out
        assert "## Threat actors" in out


# --- markdown_malware_config -------------------------------------------------


class TestMalwareConfig:
    def test_minimal(self):
        out = markdown_malware_config(
            config_id="cfg-1",
            payload={},
            malware_obj={},
            date_first=None,
            date_last=None,
            content_preview="",
            file_list=[],
        )
        assert "## Malware config" in out
        assert "cfg-1" in out

    def test_full(self):
        out = markdown_malware_config(
            config_id="cfg-1",
            payload={"hash": "abc123", "configSummary": "long" * 500},
            malware_obj={"name": "MalwareAlpha", "id": "m-1"},
            date_first="2024-01-01",
            date_last="2024-02-01",
            content_preview="some hex blob",
            file_list=[
                {
                    "name": "a.exe",
                    "md5": "x",
                    "sha1": "y",
                    "sha256": "z",
                    "timestamp": "t",
                },
                None,
            ],
        )
        assert "MalwareAlpha" in out
        assert "## Config summary" in out
        assert "## Content (preview)" in out
        assert "some hex blob" in out
        assert "## Files" in out
        assert "a.exe" in out


# --- markdown_osi_public_leak ------------------------------------------------


class TestOsiPublicLeak:
    def test_minimal(self):
        out = markdown_osi_public_leak(
            leak_id=None,
            leak_hash=None,
            created_raw=None,
            payload={},
            link_list=[],
            data_full_or_preview=None,
            matches=None,
        )
        assert "## Public leak" in out
        assert "<unknown>" in out

    def test_with_data_preview(self):
        out = markdown_osi_public_leak(
            leak_id="leak-1",
            leak_hash="hashval",
            created_raw="2024-01-01",
            payload={},
            link_list=[],
            data_full_or_preview=(False, "preview body", "Data (preview)"),
            matches=None,
        )
        assert "Data (preview)" in out
        assert "preview body" in out

    def test_with_full_data(self):
        out = markdown_osi_public_leak(
            leak_id="leak-1",
            leak_hash=None,
            created_raw=None,
            payload={},
            link_list=[],
            data_full_or_preview=(True, "full body", "ignored heading"),
            matches=None,
        )
        assert "Data (full)" in out
        assert "full body" in out

    def test_link_list_and_matches(self):
        out = markdown_osi_public_leak(
            leak_id="leak-1",
            leak_hash=None,
            created_raw=None,
            payload={},
            link_list=[
                {
                    "author": "a",
                    "link": "https://example.com",
                    "title": "t",
                    "source": "s",
                    "dateDetected": "d",
                    "datePublished": "p",
                    "hash": "h",
                },
                "skip-non-dict",
            ],
            data_full_or_preview=None,
            matches={"leak_key": "leak_value"},
        )
        assert "## Link list" in out
        assert "https://example.com" in out
        assert "## Matches" in out


# --- markdown_darkweb_forums -------------------------------------------------


class TestDarkwebForums:
    def test_minimal(self):
        out = markdown_darkweb_forums(
            post={},
            json_date_obj={},
            categories=[],
            langs=[],
            forum_url=None,
        )
        assert "## Darkweb forum post" in out
        assert "<unknown>" in out

    def test_full(self):
        out = markdown_darkweb_forums(
            post={
                "id": "post-1",
                "title": "Selling DBs",
                "forum": "forum.example.com",
                "nickname": "user_alpha",
                "thread_id": "t-1",
                "message_len": 1500,
                "description": "Full post body here.",
            },
            json_date_obj={
                "date-published": "p",
                "date-created": "c",
                "date-modified": "m",
            },
            categories=["leaks", "malware"],
            langs=["en", "ru"],
            forum_url="https://forum.example.com/threads/t-1",
        )
        assert "post-1" in out
        assert "user_alpha" in out
        assert "## Body" in out
        assert "Full post body here." in out
        assert "https://forum.example.com/threads/t-1" in out


# --- markdown_threat_report --------------------------------------------------


class TestThreatReport:
    def test_minimal(self):
        out = markdown_threat_report(obj={}, json_date_obj={})
        assert "## Threat report" in out
        assert "<unknown>" in out

    def test_full(self):
        out = markdown_threat_report(
            obj={
                "id": "tr-1",
                "title": "Nation-state campaign",
                "report_number": "CP-1",
                "is_tailored": True,
                "is_autogen": False,
                "has_iocs": True,
                "expertise": ["Hacktivism"],
                "sectors": ["finance"],
                "regions": ["EU"],
                "targeted_companies": ["ExampleCorp"],
                "targeted_partners": ["Partner"],
                "related_threat_actors": ["FIN-X"],
                "sources": ["https://example.com", "https://y"],
            },
            json_date_obj={
                "date-published": "p",
                "first-seen": "f",
                "last-seen": "l",
            },
        )
        assert "Nation-state campaign" in out
        assert "## Targeting" in out
        assert "## Sources" in out
        assert "https://example.com" in out

    def test_single_source_as_string(self):
        # sources may arrive as a bare string (not a list).
        out = markdown_threat_report(
            obj={"sources": "https://single.example.com"},
            json_date_obj={},
        )
        assert "https://single.example.com" in out


# --- markdown_threat_actor ---------------------------------------------------


class TestThreatActorMarkdown:
    def test_minimal(self):
        out = markdown_threat_actor(obj={}, json_date_obj={})
        assert "## Threat actor" in out

    def test_full_activity_section(self):
        out = markdown_threat_actor(
            obj={
                "name": "FIN-X",
                "id": "ta-1",
                "aliases": ["alias1"],
                "country": "RU",
                "is_apt": True,
                "indicators_count": 1234,
                "reports_count": 56,
                "related_threat_actors_count": 7,
            },
            json_date_obj={"first-seen": "f", "last-seen": "l"},
        )
        assert "FIN-X" in out
        assert "## Activity" in out
        assert "1234" in out

    def test_targeting_and_profile_sections(self):
        out = markdown_threat_actor(
            obj={
                "name": "x",
                "sectors": ["finance"],
                "regions": ["EU"],
                "targeted_countries": ["GB"],
                "targeted_companies": ["ExampleCorp"],
                "targeted_partners": ["Partner"],
                "expertise": ["Hacktivism"],
                "goals": ["Espionage"],
                "roles": ["agent"],
            },
            json_date_obj={},
        )
        assert "## Targeting" in out
        assert "## Profile" in out


# --- markdown_attacks_ddos ---------------------------------------------------


class TestAttacksDdos:
    def test_minimal(self):
        out = markdown_attacks_ddos(payload={}, json_date_obj={})
        assert "## DDoS attack" in out
        assert "## Target" in out

    def test_full(self):
        out = markdown_attacks_ddos(
            payload={
                "id": "att-1",
                "source": "honeypot",
                "type": "udp-flood",
                "protocol": "udp",
                "duration": 300,
                "target": {
                    "ip": "192.0.2.1",
                    "domain": "victim.example.com",
                    "url": "https://victim.example.com",
                    "port": 443,
                    "category": "web",
                    "city": "Berlin",
                    "region": "DE",
                    "country_name": "Germany",
                    "asn": "AS-1234",
                    "provider": "ISP",
                },
                "cnc": {
                    "cnc": "c2.example.com",
                    "domain": "c2.example.com",
                    "url": "https://c2.example.com",
                    "ip": "192.0.2.2",
                    "country_code": "RU",
                },
                "malware": {"name": "MalwareDelta", "id": "m-1"},
                "threat_actor": {"name": "actor-x", "id": "ta-1", "country": "RU"},
                "message_link": "https://messenger.example.com/x",
            },
            json_date_obj={
                "detection-date": "d",
                "submission-time": "s",
                "takedown-time": "t",
            },
        )
        assert "att-1" in out
        assert "Berlin" in out
        assert "## CnC" in out
        assert "## Attribution" in out
        assert "MalwareDelta" in out
        assert "actor-x" in out
        assert "## References" in out


# --- markdown_malware --------------------------------------------------------


class TestMalwareMarkdown:
    def test_minimal(self):
        out = markdown_malware(obj={}, json_date_obj={})
        assert "## Malware" in out

    def test_with_actors_and_descriptions(self):
        out = markdown_malware(
            obj={
                "name": "MalwareAlpha",
                "aliases": ["alias1"],
                "category": "banking",
                "platform": "windows",
                "langs": ["en"],
                "threat_level": "high",
                "is_published": True,
                "ta_list": [{"name": "FIN-X"}, "raw-str"],
                "threat_actor_list": [{"name": "FIN-Y"}],
                "linked_malware": [{"name": "MalwareAlphaV2"}, "raw-malware"],
                "source_countries": ["RU"],
                "geo_regions": ["EU"],
                "short_description": "Banking trojan.",
                "description": "Long description body.",
            },
            json_date_obj={"date-updated": "2024-01-01"},
        )
        assert "MalwareAlpha" in out
        assert "## Summary" in out
        assert "## Description" in out

    def test_short_equal_description_skips_description_section(self):
        out = markdown_malware(
            obj={
                "name": "x",
                "short_description": "same",
                "description": "same",
            },
            json_date_obj={},
        )
        # Header line ("## Malware: x") + "## Summary" = 2 h2-level headings.
        # When desc == short, "## Description" is suppressed.
        assert "## Summary" in out
        assert "## Description" not in out


# --- markdown_malware_cnc ----------------------------------------------------


class TestMalwareCnc:
    def test_minimal(self):
        out = markdown_malware_cnc(payload={}, json_date_obj={})
        assert "## Malware CnC" in out

    def test_full(self):
        out = markdown_malware_cnc(
            payload={
                "id": "cnc-1",
                "cnc": "c2.example.com",
                "domain": "c2.example.com",
                "url": "https://c2.example.com/x",
                "platform": "windows",
                "malware_list": [{"name": "MalwareAlpha"}, "skip"],
                "threat_actor_list": [{"name": "FIN-X"}],
                "ipv4_list": [
                    {"ip": "192.0.2.1", "asn": "AS-1", "country_name": "RU"},
                    "skip",
                ],
                "ipv6_list": [{"ip": "::1", "country_code": "GB"}],
                "file": {"md5": "a", "sha1": "b", "sha256": "c", "name": "x.exe"},
            },
            json_date_obj={
                "date-first-seen": "f",
                "date-last-seen": "l",
                "date-detected": "d",
            },
        )
        assert "MalwareAlpha" in out
        assert "## Resolved IPs" in out
        assert "192.0.2.1" in out
        assert "## Associated file" in out
        assert "x.exe" in out


# --- markdown_attacks_deface -------------------------------------------------


class TestAttacksDeface:
    def test_minimal(self):
        out = markdown_attacks_deface(payload={}, json_date_obj={})
        assert "## Website defacement" in out

    def test_full(self):
        out = markdown_attacks_deface(
            payload={
                "id": "def-1",
                "source": "monitor",
                "target_domain": "victim.example.com",
                "site_url": "https://victim.example.com",
                "mirror_link": "https://archive.example.com/x",
                "source_url": "https://defacers.example.com/v",
                "provider_domain": "cloudflare.com",
                "target_ip": {
                    "ip": "192.0.2.1",
                    "city": "NYC",
                    "region": "NY",
                    "country_name": "USA",
                    "asn": "AS-1",
                    "provider": "AT&T",
                },
                "threat_actor": {"name": "Zalim", "id": "ta-1", "is_apt": False},
            },
            json_date_obj={"detection-date": "d"},
        )
        assert "def-1" in out
        assert "## Target host" in out
        assert "AT&T" in out
        assert "## Attribution" in out
        assert "Zalim" in out


# --- markdown_attacks_phishing_group -----------------------------------------


class TestAttacksPhishingGroup:
    def test_minimal(self):
        out = markdown_attacks_phishing_group(payload={}, json_date_obj={})
        assert "## Phishing group" in out

    def test_full(self):
        out = markdown_attacks_phishing_group(
            payload={
                "id": "pg-1",
                "brand": "ExampleCorp",
                "domain": "phishing.example.com",
                "domain_title": "ExampleCorp Bank",
                "objective": "credentials",
                "count_phishing": 5,
                "source": "scan",
                "ip_list": [
                    {"ip": "192.0.2.1", "country_name": "US", "provider": "AWS"},
                    "skip",
                ],
                "phishing_list": [
                    {
                        "url": "https://fake/login",
                        "domain": "fake.com",
                        "ip": "192.0.2.1",
                        "country_code": "US",
                    },
                    "skip",
                ],
                "threat_actor": {"name": "actor", "id": "ta-1", "is_apt": False},
            },
            json_date_obj={"submission-time": "s", "takedown-time": "t"},
        )
        assert "ExampleCorp" in out
        assert "## Hosting IPs" in out
        assert "AWS" in out
        assert "## Phishing pages" in out
        assert "## Attribution" in out


# --- markdown_attacks_phishing_kit -------------------------------------------


class TestAttacksPhishingKit:
    def test_minimal(self):
        out = markdown_attacks_phishing_kit(payload={}, json_date_obj={})
        assert "## Phishing kit" in out

    def test_full(self):
        out = markdown_attacks_phishing_kit(
            payload={
                "id": "pk-1",
                "hash": "abc123",
                "login": "uploader@example.com",
                "source": "honeypot",
                "target_brand": ["ExampleCorp", "Bank"],
                "emails": ["a@b.c"],
                "downloaded_from": [
                    {
                        "url": "https://example.com/kit.zip",
                        "domain": "example.com",
                        "file_name": "kit.zip",
                        "date": "d",
                    },
                    "skip",
                ],
                "variables": [
                    {"type": "telegram", "file_path": "/bot.php"},
                    "skip",
                ],
            },
            json_date_obj={
                "detection-date": "d",
                "first-seen": "f",
                "last-seen": "l",
            },
        )
        assert "pk-1" in out
        assert "## Downloaded from" in out
        assert "## Kit variables" in out
        assert "credential values" in out  # privacy footnote


# --- markdown_osi_vulnerability ----------------------------------------------


class TestOsiVulnerability:
    def test_minimal(self):
        out = markdown_osi_vulnerability(
            vuln={},
            cvss={},
            cpe_list=[],
            json_date_obj={},
        )
        assert "## Vulnerability" in out
        assert "<unknown>" in out

    def test_full(self):
        out = markdown_osi_vulnerability(
            vuln={
                "id": "CVE-2024-1",
                "title": "RCE",
                "cvss_attack_vector": "network",
                "epss_score": 0.97,
                "epss_percentile": 0.99,
                "has_exploit": True,
                "exploit_count": 3,
                "seen_in_the_wild": True,
                "reporter": "researcher",
                "provider": "vendor",
                "bulletin_family": "linux",
                "href": "https://advisory.example.com",
                "cve_list": ["CVE-2024-1", "CVE-2024-2"],
                "description": "Critical RCE.",
                "references": ["https://example.com, https://y.com, not-a-url"],
            },
            cvss={"score": 9.8, "vector": "AV:N/AC:L/PR:N"},
            cpe_list=[
                {
                    "vendor": "linux",
                    "product": "kernel",
                    "version": "6.0",
                    "type": "os",
                    "raw_string": "cpe:2.3:o:linux:kernel:6.0",
                },
                # Duplicate — must be deduped.
                {
                    "vendor": "linux",
                    "product": "kernel",
                    "version": "6.0",
                    "type": "os",
                    "raw_string": "cpe:2.3:o:linux:kernel:6.0",
                },
                {"vendor": "x", "product": "y", "version": "1", "type": "a"},
                "skip-non-dict",
            ],
            json_date_obj={"date-published": "p", "date-modified": "m"},
        )
        assert "Critical RCE." in out
        assert "## References" in out
        assert "## Affected software" in out
        # Deduped: 2 unique CPE rows.
        assert "2 unique" in out

    def test_cpe_cap_overflow_warning(self):
        cpes = [
            {"vendor": "v", "product": "p", "version": f"{i}", "type": "x"}
            for i in range(15)
        ]
        out = markdown_osi_vulnerability(
            vuln={},
            cvss={},
            cpe_list=cpes,
            json_date_obj={},
            cpe_rows_max=5,
        )
        # 15 unique rows, table caps at 5, footer reports 10 omitted.
        assert "10 more CPE entries omitted" in out


# --- markdown_osi_git_repository ---------------------------------------------


class TestOsiGitRepository:
    def test_minimal(self):
        out = markdown_osi_git_repository(
            repo_id=None,
            name=None,
            payload={},
            date_detected=None,
            date_created=None,
            files_list=[],
            flatten_cell=_flatten_cell,
        )
        assert "## Git repository leak" in out
        assert "<unknown>" in out

    def test_full(self):
        out = markdown_osi_git_repository(
            repo_id="r-1",
            name="user/repo",
            payload={"source": "github"},
            date_detected="d",
            date_created="c",
            files_list=[
                {
                    "file_name": ".env",
                    "hash": "h1",
                    "authorName": "Dev",
                    "authorEmail": "dev@example.com",
                    "url": "https://gh/x",
                    "dataFound": "AWS_KEY",
                    "dateCreated": "c",
                    "dateDetected": "d",
                },
                "skip",
            ],
            flatten_cell=_flatten_cell,
        )
        assert "user/repo" in out
        assert "## Files" in out
        assert ".env" in out
        assert "AWS_KEY" in out


# --- markdown_hi_open_threats ------------------------------------------------


class TestHiOpenThreats:
    def _kwargs(self, **overrides):
        base = dict(
            open_threat_id="ot-1",
            title="title",
            source="src",
            source_type="blog",
            link="https://example.com",
            json_date_obj={
                "date-created": "c",
                "date-detected": "d",
                "date-updated": "u",
            },
            raw_threat_actors=[],
            raw_malware=[],
            cve_ids=[],
            tag_labels=[],
            country_codes=[],
            domain_vals=[],
            ip_vals=[],
            url_vals=[],
            valid_hashes=[],
            include_text=False,
            include_original=False,
            text="",
            original="",
            get_text_preview=lambda s: s[:100],
        )
        base.update(overrides)
        return base

    def test_minimal(self):
        out = markdown_hi_open_threats(**self._kwargs())
        assert "## Open Threat Report" in out
        assert "ot-1" in out

    def test_threat_actors_and_malware_sections(self):
        out = markdown_hi_open_threats(
            **self._kwargs(
                raw_threat_actors=[
                    {"name": "FIN-X", "id": "ta-1"},
                    {"no-name": "skip"},
                ],
                raw_malware=[{"name": "MalwareAlpha", "id": "m-1"}],
            )
        )
        assert "## Threat actors" in out
        assert "FIN-X" in out
        assert "## Malware" in out
        assert "MalwareAlpha" in out

    def test_observable_sections(self):
        out = markdown_hi_open_threats(
            **self._kwargs(
                cve_ids=["CVE-1", "CVE-2"],
                tag_labels=["t1", "t2"],
                country_codes=["US", "GB"],
                domain_vals=["d1.com", "d2.com"],
                ip_vals=["1.1.1.1"],
                url_vals=["https://u"],
                valid_hashes=["abc"],
            )
        )
        assert "## CVE" in out
        assert "CVE-1" in out
        assert "## Tags" in out
        assert "## Countries" in out
        assert "## Observables" in out
        assert "d1.com" in out

    def test_text_and_original_sections(self):
        out = markdown_hi_open_threats(
            **self._kwargs(
                include_text=True,
                include_original=True,
                text="report body text",
                original="raw fetched original",
            )
        )
        assert "## Text" in out
        assert "report body text" in out
        assert "## Original" in out
        assert "raw fetched original" in out


# --- markdown_compromised_masked_card ----------------------------------------


class TestCompromisedMaskedCard:
    def test_full(self):
        out = markdown_compromised_masked_card(
            item_id="mc-1",
            masked_card={
                "baseName": "VISA",
                "isMasked": True,
                "isDump": False,
                "isExpired": False,
                "client_ipv4_ip": "192.0.2.1",
                "price_value": 50,
                "price_currency": "USD",
            },
            card_number="4111-1111-XXXX",
            card_bins=[411111],
            card_system="VISA",
            card_type="credit",
            card_issuer="Bank",
            card_issuer_country_name="USA",
            card_issuer_country_code="US",
            card_info={"validThru": "12/25", "validThruDate": "2025-12-31"},
            card_cvv="123",
            card_pin=None,
            card_dump=None,
            cnc_domain="c2.example.com",
            cnc_url=None,
            cnc_ip="192.0.2.2",
            cnc_ipv6=None,
            cnc_country_code="RU",
            ioc_domain_on_red=True,
            ioc_url_on_red=False,
            ioc_ipv4_on_red=True,
            eval_tlp="red",
            mal_name="Mal",
            malware_obj={"id": "m-1"},
            threat_actor_names=["FIN-X"],
            source_type="leak",
            source_link="https://leak",
            owner_obj={
                "name": "Owner",
                "phone": "+1",
                "address": "1 St",
                "state": "NY",
                "zip": "10001",
                "country_code": "US",
            },
            date_detected="d",
            date_compromised="c",
        )
        assert "## Compromised masked card" in out
        assert "mc-1" in out
        assert "411111" in out
        assert "FIN-X" in out
        assert "yes (TLP=red)" in out  # ioc_domain_on_red true

    def test_minimal(self):
        out = markdown_compromised_masked_card(
            item_id="mc-1",
            masked_card={},
            card_number=None,
            card_bins=None,
            card_system=None,
            card_type=None,
            card_issuer=None,
            card_issuer_country_name=None,
            card_issuer_country_code=None,
            card_info={},
            card_cvv=None,
            card_pin=None,
            card_dump=None,
            cnc_domain=None,
            cnc_url=None,
            cnc_ip=None,
            cnc_ipv6=None,
            cnc_country_code=None,
            ioc_domain_on_red=False,
            ioc_url_on_red=False,
            ioc_ipv4_on_red=False,
            eval_tlp=None,
            mal_name=None,
            malware_obj=None,
            threat_actor_names=[],
            source_type=None,
            source_link=None,
            owner_obj={},
            date_detected=None,
            date_compromised=None,
        )
        assert "## Compromised masked card" in out


# --- markdown_ioc_note -------------------------------------------------------


class TestIocNote:
    def test_minimal(self):
        out = markdown_ioc_note(
            ioc_id="ioc-1",
            ioc_type="domain",
            ioc_value="example.com",
            json_date_obj={},
            malware_names=[],
            threat_entries=[],
        )
        assert "## IOC Details" in out
        assert "example.com" in out
        # Risk score line omitted when None.
        assert "Risk score" not in out

    def test_with_risk_score(self):
        out = markdown_ioc_note(
            ioc_id="ioc-1",
            ioc_type="domain",
            ioc_value="example.com",
            json_date_obj={"date-first-seen": "f", "date-last-seen": "l"},
            malware_names=["MalwareAlpha", "MalwareGamma"],
            threat_entries=[
                {"name": "FIN-X", "title": "campaign-1"},
                {"name": "FIN-Y"},  # no title
            ],
            risk_score=85,
        )
        assert "Risk score" in out
        assert "85" in out
        assert "## Malware" in out
        assert "MalwareAlpha" in out
        assert "## Threats" in out
        assert "FIN-X" in out
        assert "campaign-1" in out

    def test_zero_risk_score_renders(self):
        # ``0`` is not None — must still appear (low-confidence IoC).
        out = markdown_ioc_note(
            ioc_id="x",
            ioc_type="ip",
            ioc_value="192.0.2.1",
            json_date_obj={},
            malware_names=[],
            threat_entries=[],
            risk_score=0,
        )
        assert "Risk score" in out

    def test_empty_ioc_value_shows_dash(self):
        out = markdown_ioc_note(
            ioc_id="x",
            ioc_type="domain",
            ioc_value="",
            json_date_obj={},
            malware_names=[],
            threat_entries=[],
        )
        # Value cell falls back to "—" when blank.
        assert "**Value:** —" in out


# --- matches_struct_to_markdown_lines edge cases ----------------------------


class TestMatchesStructListWithNone:
    def test_list_with_none_items_renders_blank_strings(self):
        # ``None`` items inside a list emit empty cells without crashing.
        out = matches_struct_to_markdown_lines({"k": [None, "value", None]})
        assert "value" in out[-1]

    def test_list_value_truncated(self):
        # When a list serialises to a string longer than ``values_max_len``,
        # it's truncated with ``...``.
        out = matches_struct_to_markdown_lines({"k": ["x" * 600]}, values_max_len=50)
        assert "..." in out[-1]


# --- bank-card-group source-list non-dict entries ---------------------------


class TestBankCardGroupSourceListNonDict:
    def test_source_list_non_dict_items_skipped(self):
        # Bank-card-group iterates source rows; non-dict entries are
        # silently skipped without crashing.
        out = markdown_compromised_bank_card_group(
            item_id="bcg-1",
            card_number="4111...",
            card_type=None,
            card_category=None,
            card_system=None,
            card_bin=None,
            card_issuer=None,
            card_issuer_country=None,
            date_first_seen=None,
            date_last_seen=None,
            date_first_compromised=None,
            date_last_compromised=None,
            raw_ta_list=[],
            raw_source_list=["not-a-dict", None, 42, {"type": "shop", "id": "s-1"}],
            malware_names=[],
            events_table=[],
            flatten_cell=lambda v: "" if v is None else str(v),
        )
        assert "## Sources" in out
        assert "shop" in out
