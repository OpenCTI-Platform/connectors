# -*- coding: utf-8 -*-
"""Unit tests for the self-contained HTML report builder.

report_html only depends on the standard library, so these tests need neither
the network nor the connectors_sdk / pycti stack.
"""

import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

from osint_industries import report_html  # noqa: E402


def test_image_url_prefers_first_http_candidate():
    flat = {"logo": "not-a-url", "avatar": "https://cdn.test/a.png"}
    assert report_html._image_url(flat) == "https://cdn.test/a.png"


def test_image_url_none_when_no_http():
    assert report_html._image_url({"picture_url": "ftp://x", "logo": ""}) is None


def test_avatar_with_image_embeds_img_tag_and_escapes():
    out = report_html._avatar({"picture_url": "https://cdn.test/p.png?a=1&b=2"})
    assert "<img" in out
    assert "https://cdn.test/p.png?a=1&amp;b=2" in out
    assert "avatar-fallback" in out


def test_avatar_without_image_uses_fallback_icon_only():
    out = report_html._avatar({"username": "bob"})
    assert "<img" not in out
    assert "avatar-fallback" in out


def test_stringify_list_of_dicts_and_scalars():
    value = [{"k": "v", "n": 1}, "plain"]
    assert report_html._stringify(value) == "k=v, n=1 \u00b7 plain"


def test_stringify_dict():
    assert report_html._stringify({"a": 1, "b": 2}) == "a=1, b=2"


def test_stringify_scalar():
    assert report_html._stringify(42) == "42"


def test_card_renders_rows_and_hides_hidden_and_empty_fields():
    entry = {
        "module": "github",
        "shown": "jeantest",
        "flat": {
            "username": "jeantest",  # hidden field
            "id": "gh-1",
            "empty": "",  # skipped (empty)
            "company": "ACME",
        },
    }
    html_out = report_html._card(entry)
    assert "github" in html_out
    assert "jeantest" in html_out
    assert "gh-1" in html_out
    assert "ACME" in html_out
    # hidden/empty fields must not appear as data rows
    assert 'class="k">username' not in html_out
    assert 'class="k">empty' not in html_out


def test_card_with_no_visible_rows_shows_registered_placeholder():
    entry = {"module": "emailchecker", "shown": None, "flat": {"registered": True}}
    html_out = report_html._card(entry)
    assert "no extra data" in html_out


def test_build_report_html_contains_selector_count_and_cards():
    summary = [
        {"module": "github", "shown": "jeantest", "flat": {"id": "gh-1"}},
        {"module": "okru", "shown": "Jean Test", "flat": {"location": "Lyon"}},
    ]
    doc = report_html.build_report_html("test@example.com", summary)
    assert doc.startswith("<!doctype html>")
    assert "test@example.com" in doc
    assert "2 account(s)" in doc
    # cards sorted by module name: github before okru
    assert doc.index("github") < doc.index("okru")


def test_build_report_html_escapes_selector():
    doc = report_html.build_report_html("<script>&", [])
    assert "<script>&" not in doc
    assert "&lt;script&gt;&amp;" in doc
