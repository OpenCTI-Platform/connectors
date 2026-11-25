"""Code of real report pages, through the extraction and the platform import.

The fixtures are the article parts of five public report pages (scripts,
styles and images removed), so the tests cover the markup of the real pages
and not only hand-built trees. Each report is checked as the platform stores
it: the connector's HTML goes through pycti's import of a report, which
rewrites a bare <code>...</code> of the content as markdown backticks.
"""

import re
from html import unescape
from pathlib import Path

import lxml.etree
import lxml.html
import pytest
from connector.article import extract_article
from pycti.utils.opencti_stix2 import OpenCTIStix2

FIXTURES = Path(__file__).parent / "fixtures"
PAGES = {
    "crowdstrike": "https://www.crowdstrike.com/en-us/blog/"
    "adversaries-turn-vulnerability-ecosystem-against-defenders/",
    "peerstitch": "https://unit42.paloaltonetworks.com/"
    "fortimanager-cve-2024-47575-peerstitch-malware/",
    "cairn": "https://unit42.paloaltonetworks.com/cairn-framework-ai-autonomous-attacks/",
    "php2shell": "https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/",
    "rapid7": "https://www.rapid7.com/blog/post/em-patch-tuesday-november-2026",
    "bleepingcomputer": "https://www.bleepingcomputer.com/news/security/"
    "tsmc-employee-data-breach-linked-to-cloud-provider/",
}
CODE = r"<code[^>]*>(.*?)</code>"


def _stored(name: str) -> str:
    """The report content as the platform stores it after the worker import."""
    html = (FIXTURES / f"{name}.html").read_text(encoding="utf-8")
    article = extract_article(PAGES[name], html)
    assert article is not None
    # convert_markdown does not use its instance: the import path, unchanged.
    return OpenCTIStix2.convert_markdown(None, article.html)


def _blocks(html: str) -> list[str]:
    return [
        unescape(block)
        for block in re.findall(r"<pre>" + CODE + r"</pre>", html, re.DOTALL)
    ]


def _outside_code(html: str) -> str:
    return re.sub(CODE, "", html, flags=re.DOTALL)


@pytest.mark.parametrize("name", list(PAGES))
def test_no_backtick_outside_the_code_of_the_page(name):
    assert "`" not in _outside_code(_stored(name))


def test_inline_code_of_a_report_stays_inline_code():
    html = _stored("crowdstrike")
    inline = [unescape(code) for code in re.findall(CODE, html, re.DOTALL)]
    for value in (
        "de8d1b25e8965dc98c62d675ee7c451ed12502194890f6cc691322ad66f3abf4",
        "www-data",
        "root",
        "exec()",
        "157.20.182[.]49",
        "test",
        "test2",
        "FortiWiFi",
        "super_admin",
    ):
        assert value in inline
    assert "<pre" not in html
    assert re.search(r"default web user <code[^>]*>www-data</code> to <code", html)
    assert re.search(r"<td><code[^>]*>test</code></td>", html)


def test_yara_rule_is_one_code_block_without_a_fence():
    blocks = _blocks(_stored("peerstitch"))
    assert len(blocks) == 1
    assert blocks[0].startswith("rule u42_apt_linux_PEERSTITCH_fortigate_implant\n{")
    assert blocks[0].rstrip().endswith("}")
    assert "`" not in blocks[0]


def test_prompt_blocks_are_code_blocks_without_a_fence():
    blocks = _blocks(_stored("cairn"))
    assert len(blocks) == 2
    assert blocks[0].startswith("以拿到实质性高价值权限为止")
    assert blocks[1].startswith("你工作在已获授权的安全测试")
    assert not any(block.startswith("`") or block.endswith("`") for block in blocks)


def _section_table(html: str, heading: str) -> lxml.etree._Element:
    """The table right after a heading of the stored report."""
    document = lxml.html.fromstring(html)
    (title,) = document.xpath(f'//h2[normalize-space()="{heading}"]')
    table = title.getnext()
    assert table.tag == "table"
    return table


@pytest.mark.parametrize(
    ("heading", "rows"),
    [("Zero-Day Vulnerabilities: Known Exploited", 1), ("Critical RCEs and EoPs", 21)],
)
def test_markdown_pipe_tables_of_a_report_are_tables(heading, rows):
    table = _section_table(_stored("rapid7"), heading)
    assert len(table.xpath("./tr")) == rows
    for row in table.xpath("./tr"):
        cells = row.xpath("./td")
        assert len(cells) == 5
        (link,) = cells[0].xpath("./a")
        assert link.get("href").startswith(
            "https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-"
        )
        assert link.text == cells[0].text_content().strip()
        assert link.text.startswith("CVE-")


def test_html_tables_of_a_report_are_unchanged_and_no_pipe_text_is_left():
    html = _stored("rapid7")
    document = lxml.html.fromstring(html)
    tables = document.xpath("//table")
    # 13 HTML tables on the page, plus the 2 written from pipe text.
    assert len(tables) == 15
    headed = [table for table in tables if table.xpath("./tr[1]/th")]
    assert len(headed) == 13
    for table in headed:
        assert [th.text for th in table.xpath("./tr[1]/th")][:2] == ["CVE", "Title"]
    assert not re.search(r"<p>\s*\|", html)


def test_headings_left_without_content_by_the_images_are_dropped():
    html = _stored("rapid7")
    assert "Summary charts" not in html
    # Followed by another h2 at once: nothing under it either.
    assert "Summary tables" not in html
    assert "<h2>Vulnerabilities by Product Family</h2>" in html
    assert "<h3>Apps vulnerabilities</h3>" in html


def test_sponsored_ad_unit_inside_the_article_body_is_dropped():
    html = (FIXTURES / "bleepingcomputer.html").read_text(encoding="utf-8")
    article = extract_article(PAGES["bleepingcomputer"], html)
    for text in (article.text, article.html):
        assert "Uncover email threats" not in text
        assert "Adaptive Security" not in text
        assert "Start your free email security scan" not in text
        assert "adaptivesecurity.com" not in text
    assert article.text.rstrip().endswith(
        "A spokesperson declined to comment at this stage."
    )
    page = lxml.html.fromstring(html)
    (body,) = page.xpath('//div[@class="articleBody"]')
    paragraphs = [
        re.sub(r"\s+", " ", p.text_content()).strip()
        for p in body.xpath("./p")
        if p.text_content().strip()
    ]
    assert len(paragraphs) == 15
    # The stored content's text: the text output writes links as markdown.
    text = re.sub(r"\s+", " ", lxml.html.fromstring(article.html).text_content())
    for paragraph in paragraphs:
        assert paragraph in text


def test_hunting_queries_are_code_blocks_without_a_fence():
    blocks = _blocks(_stored("php2shell"))
    assert len(blocks) == 2
    assert all(block.startswith("// Description:") for block in blocks)
    assert not any(block.rstrip().endswith("`") for block in blocks)
