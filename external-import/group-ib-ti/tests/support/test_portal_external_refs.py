from __future__ import annotations

from support.portal_external_refs import (
    _merge_description,
    chat_portal_link_row,
    portal_external_ref_rows,
    portal_link_row,
    portal_link_tuple,
)


class TestMergeDescription:
    def test_both_none_returns_empty(self):
        assert _merge_description(None, None) == ""

    def test_both_empty_strings_returns_empty(self):
        assert _merge_description("", "") == ""

    def test_short_only(self):
        assert _merge_description("hello", None) == "hello"

    def test_long_only(self):
        assert _merge_description(None, "world") == "world"

    def test_both_joined_with_paragraph_break(self):
        out = _merge_description("short", "long")
        assert out == "short\n\nlong"

    def test_html_in_inputs_stripped(self):
        # Both inputs flow through normalize_description.
        out = _merge_description("<b>short</b>", "<p>long</p>")
        assert "<" not in out and ">" not in out
        assert "short" in out and "long" in out

    def test_whitespace_only_dropped(self):
        # normalize_description returns "" for whitespace-only input.
        assert _merge_description("   ", None) == ""


class TestPortalLinkTuple:
    def test_none_returns_none(self):
        assert portal_link_tuple(None) is None

    def test_non_string_returns_none(self):
        assert portal_link_tuple(123) is None
        assert portal_link_tuple(["url"]) is None

    def test_empty_string_returns_none(self):
        assert portal_link_tuple("") is None
        assert portal_link_tuple("   ") is None

    def test_known_prefix_apt_threat(self):
        link = "https://tap.group-ib.com/ta/last-threats?threat=abc123"
        row = portal_link_tuple(link)
        assert row is not None
        record_id, url, desc = row
        assert record_id == "abc123"
        assert url == link
        assert desc == ""

    def test_known_prefix_with_query_fragment_stripped(self):
        # Anything after ``&`` or ``#`` is dropped from the record_id, but
        # the url returned is the canonical generated one (no extras).
        link = "https://tap.group-ib.com/ta/last-threats?threat=abc123&foo=bar"
        record_id, url, _ = portal_link_tuple(link)
        assert record_id == "abc123"
        assert url == "https://tap.group-ib.com/ta/last-threats?threat=abc123"

    def test_unknown_url_passes_through(self):
        link = "https://example.com/anywhere?id=xyz"
        row = portal_link_tuple(link)
        assert row is not None
        record_id, url, _ = row
        assert record_id is None
        assert url == link

    def test_description_payload_propagated(self):
        link = "https://tap.group-ib.com/ta/last-threats?threat=t1"
        row = portal_link_tuple(link, extra_short="short body", extra_long="long body")
        assert row is not None
        _, _, desc = row
        assert "short body" in desc and "long body" in desc

    def test_record_id_lstripped(self):
        # Leading/trailing whitespace on the input URL is stripped before
        # the prefix match runs.
        link = "  https://tap.group-ib.com/ta/last-threats?threat=t1  "
        record_id, _, _ = portal_link_tuple(link)
        assert record_id == "t1"


class TestPortalLinkRow:
    def test_simple_collection(self):
        row = portal_link_row("apt/threat", record_id="r1")
        assert row is not None
        record_id, url, desc = row
        assert record_id == "r1"
        assert url == "https://tap.group-ib.com/ta/last-threats?threat=r1"
        assert desc == ""

    def test_no_record_id_returns_none(self):
        # Simple-template collection without a record_id can't build a URL.
        assert portal_link_row("apt/threat") is None
        assert portal_link_row("apt/threat", record_id=None) is None

    def test_unknown_collection_returns_none(self):
        assert portal_link_row("nope/never") is None

    def test_multi_part_collection_via_fields(self):
        row = portal_link_row(
            "compromised/messenger",
            fields={"chatStat.id": "11", "id": "22"},
        )
        assert row is not None
        record_id, url, _ = row
        # ``portal_link_row`` only sets record_id when one is passed
        # explicitly; for fields-based templates it stays None.
        assert record_id is None
        assert url == "https://tap.group-ib.com/ta/im?chatId=11&msg=22"

    def test_multi_part_missing_field_returns_none(self):
        assert (
            portal_link_row("compromised/messenger", fields={"chatStat.id": "11"})
            is None
        )

    def test_record_id_coerced_to_str(self):
        row = portal_link_row("apt/threat", record_id=42)
        assert row is not None
        record_id, url, _ = row
        assert record_id == "42"
        assert url.endswith("=42")


class TestChatPortalLinkRow:
    def test_discord_with_both_ids(self):
        row = chat_portal_link_row("discord", "ch1", "msg1")
        assert row is not None
        _, url, _ = row
        assert "collection=discord" in url
        assert "chatId=ch1" in url
        assert "msg=msg1" in url

    def test_messenger_with_both_ids(self):
        row = chat_portal_link_row("messenger", "ch1", "msg1")
        assert row is not None
        _, url, _ = row
        assert "chatId=ch1" in url
        assert "msg=msg1" in url

    def test_messenger_is_default_for_unknown_platform(self):
        # Anything that isn't ``"discord"`` falls through to the messenger
        # template (Telegram), per the helper's contract.
        row = chat_portal_link_row("telegram", "ch1", "msg1")
        assert row is not None
        _, url, _ = row
        assert "chatId=ch1" in url

    def test_missing_chat_id_returns_none(self):
        assert chat_portal_link_row("discord", None, "msg1") is None
        assert chat_portal_link_row("discord", "", "msg1") is None
        assert chat_portal_link_row("discord", 0, "msg1") is None

    def test_missing_msg_id_returns_none(self):
        assert chat_portal_link_row("discord", "ch1", None) is None
        assert chat_portal_link_row("discord", "ch1", "") is None

    def test_int_ids_coerced(self):
        row = chat_portal_link_row("messenger", 1234, 5678)
        assert row is not None
        _, url, _ = row
        assert "chatId=1234" in url and "msg=5678" in url


class TestPortalExternalRefRows:
    def test_empty_dict(self):
        assert portal_external_ref_rows({}) == []

    def test_dict_without_portal_link_returns_empty(self):
        assert portal_external_ref_rows({"foo": "bar"}) == []

    def test_dict_with_portal_link(self):
        obj = {
            "portal_link": "https://tap.group-ib.com/ta/last-threats?threat=t1",
            "description": "body",
        }
        rows = portal_external_ref_rows(obj)
        assert len(rows) == 1
        record_id, url, desc = rows[0]
        assert record_id == "t1"
        assert url == "https://tap.group-ib.com/ta/last-threats?threat=t1"
        assert "body" in desc

    def test_dict_prefers_short_description_camelcase(self):
        obj = {
            "portal_link": "https://tap.group-ib.com/ta/last-threats?threat=t1",
            "shortDescription": "camel",
            "description": "long",
        }
        rows = portal_external_ref_rows(obj)
        assert "camel" in rows[0][2]
        assert "long" in rows[0][2]

    def test_dict_prefers_short_description_snakecase(self):
        obj = {
            "portal_link": "https://tap.group-ib.com/ta/last-threats?threat=t1",
            "short_description": "snake",
        }
        rows = portal_external_ref_rows(obj)
        assert "snake" in rows[0][2]

    def test_list_input_emits_one_row_per_item(self):
        objs = [
            {
                "portal_link": ("https://tap.group-ib.com/ta/last-threats?threat=t1"),
            },
            {
                "portal_link": ("https://tap.group-ib.com/ta/last-threats?threat=t2"),
            },
        ]
        rows = portal_external_ref_rows(objs)
        assert [r[0] for r in rows] == ["t1", "t2"]

    def test_list_skips_non_dict_items(self):
        objs = [
            None,
            "string-item",
            42,
            {
                "portal_link": ("https://tap.group-ib.com/ta/last-threats?threat=t1"),
            },
        ]
        rows = portal_external_ref_rows(objs)
        assert len(rows) == 1
        assert rows[0][0] == "t1"

    def test_list_skips_dicts_without_portal_link(self):
        objs = [{"unrelated": "x"}, {"portal_link": ""}]
        assert portal_external_ref_rows(objs) == []

    def test_non_dict_non_list_returns_empty(self):
        assert portal_external_ref_rows("string") == []
        assert portal_external_ref_rows(123) == []
        assert portal_external_ref_rows(None) == []
