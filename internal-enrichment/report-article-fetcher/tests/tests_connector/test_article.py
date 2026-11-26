import re
import socket
import sys
import threading
from html import unescape
from http.server import BaseHTTPRequestHandler, HTTPServer

import lxml.etree
import lxml.html
import pytest
from connector.article import (
    Article,
    FetchError,
    _code_lines,
    _drop_empty_headings,
    _is_paid_link,
    _restore_code_elements,
    article_match,
    check_public_url,
    extract_article,
    fetch_html,
    find_article_reference,
    judge,
)

NAME = "Akira ransomware targets VPN appliances"
RSS_REFERENCE = {
    "source_name": NAME,
    "description": f"Some feed {NAME}. Retrieved 2026-11-03T10:00:00.000Z.",
    "url": "https://blog.example.com/akira-ransomware-vpn-appliances",
}
OTHER_REFERENCE = {"source_name": "MITRE", "url": "https://attack.mitre.org/"}


def _article(text: str, title: str | None = NAME, url: str = RSS_REFERENCE["url"]):
    return Article(url=url, title=title, html=f"<p>{text}</p>", text=text)


def test_finds_the_reference_written_by_the_rss_ingestion():
    report = {"name": NAME, "external_references": [OTHER_REFERENCE, RSS_REFERENCE]}
    assert find_article_reference(report, False) == RSS_REFERENCE


def test_refuses_a_report_without_an_rss_reference():
    report = {"name": NAME, "external_references": [OTHER_REFERENCE]}
    with pytest.raises(ValueError):
        find_article_reference(report, False)
    assert find_article_reference(report, True) == OTHER_REFERENCE


def test_refuses_a_report_with_several_references_when_none_is_rss():
    report = {"name": NAME, "external_references": [OTHER_REFERENCE] * 2}
    with pytest.raises(ValueError):
        find_article_reference(report, True)


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "::1"]
)
def test_refuses_internal_addresses(monkeypatch, address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *_: [(family, 0, 0, "", (address, 0))]
    )
    with pytest.raises(FetchError):
        check_public_url("https://feed-controlled.example.com/post")


def test_refuses_other_schemes():
    with pytest.raises(FetchError):
        check_public_url("file:///etc/passwd")


def test_accepts_a_longer_article_with_the_same_title():
    verdict = judge(_article("word " * 400), NAME, "teaser " * 20, 500, 1.5, 0.6)
    assert verdict.accepted


def test_never_replaces_a_full_text_with_less():
    verdict = judge(_article("word " * 400), NAME, "full " * 1000, 500, 1.5, 0.6)
    assert not verdict.accepted


def test_rejects_an_anti_bot_page():
    text = "Just a moment... Checking your browser before accessing. " * 20
    verdict = judge(_article(text, title="Just a moment..."), NAME, "", 500, 1.5, 0.6)
    assert not verdict.accepted
    assert "blocked" in verdict.reason


def test_rejects_another_page():
    article = _article(
        "word " * 400, title="Our blog", url="https://blog.example.com/archive"
    )
    assert not judge(article, NAME, "", 500, 1.5, 0.6).accepted


def test_matches_a_generic_page_title_on_the_text():
    article = _article(f"Avis du CERT-FR. Objet : {NAME}. " + "word " * 400)
    article.title = "Avis du CERT-FR"
    assert article_match(f"{NAME} (19 octobre 2026)", article) >= 0.6


def test_matches_a_renamed_post_on_its_url_slug():
    article = _article("word " * 400, title="A completely new headline")
    assert article_match(NAME, article) == 1.0


def test_fills_an_empty_content_whatever_the_description():
    # The description is never touched, so an empty content replaces nothing
    verdict = judge(_article("word " * 400), NAME, "", 500, 1.5, 0.6)
    assert verdict.accepted


def test_keeps_tables_nested_in_wrapper_divs():
    sha256 = "3768f470934a111f1c3e3d098eb1392a3cb6f3e298ef5fd2a6309e6a98ee1e18"
    paragraphs = "".join(
        f"<p>Paragraph {i} of the analysis of the botnet and its operators.</p>"
        for i in range(30)
    )
    table = (
        "<table><tr><td><p><span>Tool</span></p></td><td><p>SHA256</p></td></tr>"
        f"<tr><td><p><span>XCPE</span></p></td><td><p>{sha256}</p></td></tr></table>"
    )
    wrapped = '<div style="overflow-x:auto">' * 12 + table + "</div>" * 12
    html = (
        f"<html><head><title>{NAME}</title></head><body><article><h1>{NAME}</h1>"
        f"{paragraphs}<h3>Indicators of Compromise</h3>{wrapped}"
        f"<p>Closing words of the article.</p></article></body></html>"
    )
    article = extract_article(RSS_REFERENCE["url"], html)
    assert "<table" in article.html
    assert sha256 in article.html


def test_keeps_indicators_listed_one_per_div():
    paragraphs = "".join(
        f"<p>Paragraph {i} of the report on the phishing campaign and its loaders.</p>"
        for i in range(30)
    )
    indicators = (
        "<section><span>MD5</span><div><div>"
        "<div>0585a54a7edc2b8d84de952c748b62d8</div>"
        "<div>05c510fc70d4bdeba2253d563720ff24</div></div></div>"
        "<span>IP</span><div><div><div>103[.]81[.]116[.]10</div></div></div>"
        "<span>URL</span><div><div><div>hxxps[:]//link24[.]kr/3CQmvGA</div>"
        "</div></div></section>"
    )
    html = (
        f"<html><head><title>{NAME}</title></head><body><article><h1>{NAME}</h1>"
        f"{paragraphs}{indicators}</article></body></html>"
    )
    article = extract_article(RSS_REFERENCE["url"], html)
    for indicator in (
        "0585a54a7edc2b8d84de952c748b62d8",
        "103[.]81[.]116[.]10",
        "hxxps[:]//link24[.]kr/3CQmvGA",
    ):
        assert indicator in article.html


def test_keeps_tables_inside_embed_blocks():
    paragraphs = "".join(
        f"<p>Paragraph {i} of the hunt for the command and control servers.</p>"
        for i in range(30)
    )
    embed = (
        '<div class="w-embed"><!-- IOC table --><link href="https://fonts.example/x"'
        ' rel="stylesheet"><style>.ioc { color: red; }</style>'
        '<div class="ioc-wrap"><table class="ioc"><thead><tr><th>C2 IP</th>'
        "<th>First Seen</th></tr></thead><tbody><tr><td>194.87.128.243</td>"
        "<td>2026-02-07</td></tr></tbody></table></div></div>"
    )
    html = (
        f"<html><head><title>{NAME}</title></head><body><article><h1>{NAME}</h1>"
        f"{paragraphs}<h4>Indicators of Compromise</h4>{embed}</article></body></html>"
    )
    article = extract_article(RSS_REFERENCE["url"], html)
    assert "<table" in article.html
    assert "194.87.128.243" in article.html


# The shape of a vendor blog post whose headings carry in-page anchors: an
# <a id> or <a name> with no href before the heading text.
ANCHORED_POST = (
    f"<html><head><title>{NAME}</title></head><body><article><h1>{NAME}</h1>"
    + "".join(
        f"<p>Paragraph {i} of the analysis of the intrusion and its tooling.</p>"
        for i in range(20)
    )
    + '<h2><a id="overview"></a>Overview</h2>'
    + "<p>The operators gained access through an unpatched appliance.</p>"
    + '<h3><a name="tooling"></a>Tooling</h3>'
    + "<p>They deployed a loader described in "
    + '<a href="https://intel.example.org/loader">this analysis</a>.</p>'
    + '<h2><a href="#iocs">Indicators of Compromise</a></h2>'
    + "<ul><li>194.87.128.243</li><li>malicious-domain.example</li></ul>"
    + "<p>Closing words of the article.</p></article></body></html>"
)

_NON_VOID_SELF_CLOSED = re.compile(
    r"<(?!(?:area|base|br|col|embed|hr|img|input|link|meta|source|track|wbr)\b)"
    r"[a-z][a-z0-9]*\b[^>]*/>",
    re.IGNORECASE,
)


def test_drops_empty_heading_anchors():
    article = extract_article(RSS_REFERENCE["url"], ANCHORED_POST)
    assert "<h2>Overview</h2>" in article.html
    assert "<h3>Tooling</h3>" in article.html
    assert '<a href=""' not in article.html
    assert not _NON_VOID_SELF_CLOSED.search(article.html)


def test_drops_fragment_links_and_keeps_real_links():
    article = extract_article(RSS_REFERENCE["url"], ANCHORED_POST)
    assert '<a href="https://intel.example.org/loader">this analysis</a>' in (
        article.html
    )
    assert 'href="#' not in article.html
    assert "Indicators of Compromise" in article.html
    assert "194.87.128.243" in article.html


def test_keeps_an_explicit_link_to_a_fragment_of_the_site_root():
    html = ANCHORED_POST.replace(
        "<p>Closing words of the article.</p>",
        '<p>See <a href="https://blog.example.com/#about">the team</a>.</p>'
        "<p>Closing words of the article.</p>",
    )
    article = extract_article(RSS_REFERENCE["url"], html)
    assert 'href="https://blog.example.com/#about"' in article.html
    assert "blog.example.com#iocs" not in article.html
    assert "blog.example.com/#iocs" not in article.html


def test_never_self_closes_an_element():
    html = (
        f"<html><head><title>{NAME}</title></head><body><article><h1>{NAME}</h1>"
        + "".join(
            f"<p>Paragraph {i} of the report on the campaign.<span></span></p>"
            for i in range(20)
        )
        + "<table><tr><td></td><td>2026-02-07</td></tr></table>"
        + "<p>Closing words.</p></article></body></html>"
    )
    article = extract_article(RSS_REFERENCE["url"], html)
    assert not _NON_VOID_SELF_CLOSED.search(article.html)


# A hunting query shown by a syntax highlighter: the second line is
# indented, the third is empty.
QUERY = [
    "config case_sensitive = false",
    "    | dataset = xdr_data",
    "",
    '| filter action_process_image_name ~= "php"',
]


def _post(block: str, after: str = "") -> str:
    return (
        f"<html><head><title>{NAME}</title></head><body><article><h1>{NAME}</h1>"
        + "".join(
            f"<p>Paragraph {i} of the threat brief and its hunting queries.</p>"
            for i in range(20)
        )
        + f"<h2>Hunting queries</h2>{block}{after}"
        + "<p>Closing words of the article.</p></article></body></html>"
    )


def _crayon(lines: list[str]) -> str:
    """Crayon (WordPress): a <div> per number, a <div> per line of code."""
    numbers = "".join(
        f'<div class="crayon-num" data-line="c-{n}">{n}</div>'
        for n in range(1, len(lines) + 1)
    )
    code = "".join(
        f'<div class="crayon-line" id="c-{n}">'
        + (
            "&nbsp;"
            if not line
            else line.replace(" ", '<span class="crayon-h"> </span>', 1)
        )
        + "</div>"
        for n, line in enumerate(lines, 1)
    )
    return (
        '<div class="crayon-syntax"><div class="crayon-main">'
        '<table class="crayon-table"><tbody><tr class="crayon-row">'
        f'<td class="crayon-nums"><div class="crayon-nums-content">{numbers}</div></td>'
        f'<td class="crayon-code"><div class="crayon-pre">{code}</div></td>'
        "</tr></tbody></table></div></div>"
    )


def _pygments(lines: list[str]) -> str:
    """Pygments / SyntaxHighlighter: the numbers and the code in two <pre>."""
    numbers = "\n".join(str(n) for n in range(1, len(lines) + 1))
    code = "\n".join(f'<span class="k">{line[:6]}</span>{line[6:]}' for line in lines)
    return (
        '<div class="highlight"><table class="highlighttable"><tr>'
        f'<td class="linenos"><div class="linenodiv"><pre>{numbers}</pre></div></td>'
        f'<td class="code"><div class="highlight"><pre>{code}\n</pre></div></td>'
        "</tr></table></div>"
    )


def _github(lines: list[str]) -> str:
    """GitHub-style blob table: one row per line, the number in an attribute."""
    rows = "".join(
        f'<tr><td id="L{n}" class="blob-num" data-line-number="{n}"></td>'
        f'<td class="blob-code">{line}</td></tr>'
        for n, line in enumerate(lines, 1)
    )
    return f'<table class="highlight"><tbody>{rows}</tbody></table>'


# The connector writes every code element <code translate="no">, so pycti's
# import does not rewrite it as markdown backticks.
CODE = '<code translate="no">'


def _code_blocks(html: str) -> list[str]:
    return re.findall(r'<pre><code translate="no">(.*?)</code></pre>', html, re.DOTALL)


@pytest.mark.parametrize("markup", [_crayon, _pygments, _github])
def test_turns_a_line_numbered_code_table_into_one_code_block(markup):
    article = extract_article(RSS_REFERENCE["url"], _post(markup(QUERY)))
    blocks = _code_blocks(article.html)
    assert len(blocks) == 1
    assert unescape(blocks[0]) == "\n".join(QUERY)
    assert "<table" not in article.html
    assert "<p>1</p>" not in article.html


def test_keeps_each_code_block_of_a_page_apart():
    """A threat brief with two hunting queries of 117 and 12 lines."""
    first = (QUERY * 30)[:117]
    second = ["dataset = panw_ngfw_threat_raw", '  | filter sub_type = "vuln"'] * 6
    article = extract_article(
        RSS_REFERENCE["url"], _post(_crayon(first), _crayon(second))
    )
    blocks = [unescape(block) for block in _code_blocks(article.html)]
    assert blocks == ["\n".join(first), "\n".join(second)]
    assert "<p>117</p>" not in article.html


def test_keeps_a_table_whose_first_column_counts_the_rows():
    table = (
        "<table><tr><th>#</th><th>Indicator</th></tr>"
        "<tr><td>1</td><td>194.87.128.243</td></tr>"
        "<tr><td>2</td><td>malicious-domain.example</td></tr>"
        "<tr><td>3</td><td>3768f470934a111f1c3e3d098eb1392a</td></tr></table>"
    )
    article = extract_article(RSS_REFERENCE["url"], _post(table))
    assert "<table" in article.html
    assert "194.87.128.243" in article.html
    assert not _code_blocks(article.html)


def test_keeps_a_two_cell_table_whose_numbers_do_not_match_the_code():
    table = (
        "<table><tr><td>1<br>2<br>3</td>"
        "<td>194.87.128.243<br>malicious-domain.example</td></tr></table>"
    )
    article = extract_article(RSS_REFERENCE["url"], _post(table))
    assert "194.87.128.243" in article.html
    assert not _code_blocks(article.html)


def test_keeps_an_unmarked_two_cell_table_whose_numbers_match_its_lines():
    """Same shape as a gutter table, but no highlighter class and no <pre>."""
    table = (
        "<table><tr><td>1<br>2</td>"
        '<td><a href="https://malicious-domain.example/">194.87.128.243</a>'
        "<br><b>malicious-domain.example</b></td></tr></table>"
    )
    article = extract_article(RSS_REFERENCE["url"], _post(table))
    assert "194.87.128.243" in article.html
    assert "malicious-domain.example" in article.html
    assert not _code_blocks(article.html)


def test_keeps_an_unmarked_table_with_line_number_attributes():
    rows = "".join(
        f'<tr><td data-line-number="{n}"></td><td>{value}</td></tr>'
        for n, value in enumerate(
            ["194.87.128.243", "malicious-domain.example", "3768f470934a"], 1
        )
    )
    article = extract_article(RSS_REFERENCE["url"], _post(f"<table>{rows}</table>"))
    assert "194.87.128.243" in article.html
    assert not _code_blocks(article.html)


HASH = "de8d4e2bd3a6a3ab9e22e19c6c1c4f8f5e1c7a7f2c5a1e3b2d9f8e7c6b5aabf4"


def _tables(html: str) -> list[list[list[tuple[str, str]]]]:
    """Each table of the HTML: its rows, each a list of (cell tag, text)."""
    document = lxml.html.fromstring(html)
    return [
        [
            [(cell.tag, cell.text_content().strip()) for cell in row]
            for row in table.iter("tr")
        ]
        for table in document.iter("table")
    ]


def test_turns_a_markdown_pipe_paragraph_into_a_table():
    article = extract_article(
        RSS_REFERENCE["url"],
        _post(
            '<p>| <a href="https://msrc.example.com/CVE-2026-1">CVE-2026-1</a>'
            " | Title one | <em>Detected</em> | 9.0 |\n"
            '| <a href="https://msrc.example.com/CVE-2026-2">CVE-2026-2</a>'
            " | Title two | N/A | 7.5 |</p>"
        ),
    )
    assert "| " not in _section(article.html)
    assert _tables(article.html) == [
        [
            [("td", "CVE-2026-1"), ("td", "Title one"), ("td", "Detected")]
            + [("td", "9.0")],
            [("td", "CVE-2026-2"), ("td", "Title two"), ("td", "N/A")]
            + [("td", "7.5")],
        ]
    ]
    assert '<td><a href="https://msrc.example.com/CVE-2026-1">CVE-2026-1</a></td>' in (
        article.html
    )
    assert "<td><i>Detected</i></td>" in article.html


def test_turns_the_line_before_a_separator_into_a_header_row():
    article = extract_article(
        RSS_REFERENCE["url"], _post("<p>| A | B |\n|---|:---:|\n| 1 | 2 |</p>")
    )
    assert _tables(article.html) == [
        [[("th", "A"), ("th", "B")], [("td", "1"), ("td", "2")]]
    ]


def test_a_pipe_in_inline_code_is_not_a_cell_separator():
    article = extract_article(
        RSS_REFERENCE["url"],
        _post("<p>| <code>a|b</code> | c |\n| d | e |</p>"),
    )
    assert _tables(article.html) == [
        [[("td", "a|b"), ("td", "c")], [("td", "d"), ("td", "e")]]
    ]
    assert f"<td>{CODE}a|b</code></td>" in article.html


def test_an_escaped_pipe_is_a_literal_pipe_of_the_cell():
    article = extract_article(
        RSS_REFERENCE["url"],
        _post("<p>| a \\| b | c |\n| d | e |</p>"),
    )
    assert _tables(article.html) == [
        [[("td", "a | b"), ("td", "c")], [("td", "d"), ("td", "e")]]
    ]


def test_a_pipe_after_an_escaped_backslash_is_a_cell_separator():
    article = extract_article(
        RSS_REFERENCE["url"],
        _post("<p>| C:\\\\ | c |\n| d \\\\\\| e | f |</p>"),
    )
    assert _tables(article.html) == [
        [[("td", "C:\\"), ("td", "c")], [("td", "d \\| e"), ("td", "f")]]
    ]


@pytest.mark.parametrize(
    "block",
    [
        "<p>Chain the commands with a | b to read the output.</p>",
        "<p>| one cell |\n| other |</p>",
        "<p>| a | b |\n| c | d | e |</p>",
        "<p>| a | b |\nand some prose after the rows.</p>",
    ],
)
def test_leaves_a_paragraph_that_is_not_a_pipe_table(block):
    article = extract_article(RSS_REFERENCE["url"], _post(block))
    assert "<table" not in article.html
    # The paragraph is kept as text (its line breaks joined, as before).
    text = " ".join(lxml.html.fromstring(block).text_content().split())
    assert f"<p>{text}</p>" in unescape(article.html)


def test_leaves_pipe_lines_of_a_code_block():
    article = extract_article(
        RSS_REFERENCE["url"], _post("<pre><code>| a | b |\n| c | d |</code></pre>")
    )
    assert "<table" not in article.html
    assert _code_blocks(article.html) == ["| a | b |\n| c | d |"]


def test_drops_a_heading_whose_section_held_only_images():
    article = extract_article(
        RSS_REFERENCE["url"],
        _post(
            "<p>Queries of the brief.</p>"
            '<h2>Summary charts</h2><p><img src="https://cdn.example.com/a.png"></p>'
            '<span><img src="https://cdn.example.com/b.png"></span>'
            "<h2>Summary tables</h2><h3>Apps</h3><p>Apps text.</p>"
        ),
    )
    assert "Summary charts" not in article.html
    assert "<h2>Summary tables</h2>" in article.html
    assert "<h3>Apps</h3>" in article.html
    assert "<h2>Hunting queries</h2>" in article.html


@pytest.mark.parametrize(
    ("markup", "kept"),
    [
        ("<h2>A</h2><p>x</p><h2>B</h2>", ["A"]),
        ("<h2>A</h2><h3>B</h3><h2>C</h2><p>x</p>", ["C"]),
        ("<h2>A</h2><h3>B</h3><p>x</p><h2>C</h2>", ["A", "B"]),
        ("<h2>A</h2><div><p>x</p></div>", ["A"]),
        ("<h2>A</h2>tail text<h2>B</h2><p>x</p>", ["A", "B"]),
    ],
)
def test_drops_only_the_headings_with_nothing_under_them(markup, kept):
    tree = lxml.html.fromstring(f"<div>{markup}</div>")
    _drop_empty_headings(tree)
    assert [heading.text for heading in tree.xpath("//h2|//h3")] == kept
    assert "x" in tree.text_content()


def _section(html: str) -> str:
    """The extracted HTML between the code section's heading and the end."""
    return html[html.index("<h2>Hunting queries</h2>") : html.index("Closing words")]


def test_keeps_inline_code_of_a_paragraph_inline():
    article = extract_article(
        RSS_REFERENCE["url"], _post(f"<p>(SHA256 hash: <code>{HASH}</code>)</p>")
    )
    assert f"<p>(SHA256 hash: {CODE}{HASH}</code>)</p>" in article.html
    assert "<pre" not in _section(article.html)


def test_keeps_two_inline_codes_in_one_paragraph():
    article = extract_article(
        RSS_REFERENCE["url"],
        _post(
            "<p>from the default web user <code>www-data</code> to <code>root</code></p>"
        ),
    )
    assert (
        f"<p>from the default web user {CODE}www-data</code> to {CODE}root</code></p>"
        in article.html
    )
    assert "<pre" not in _section(article.html)


def test_keeps_inline_code_in_table_cells_and_list_items():
    table = (
        "<table><tr><th>Function</th><th>File</th></tr>"
        "<tr><td><code>exec()</code></td><td><code>a.dll</code></td></tr>"
        "<tr><td><code>system()</code></td><td><code>b.exe</code></td></tr></table>"
        "<ul><li>run <code>whoami</code> first</li><li><code>ls</code></li></ul>"
    )
    article = extract_article(RSS_REFERENCE["url"], _post(table))
    section = _section(article.html)
    assert "<table>" in section
    for value in ("exec()", "a.dll", "system()", "b.exe"):
        assert f"<td>{CODE}{value}</code></td>" in section
    assert f"<li>run {CODE}whoami</code> first</li>" in section
    assert f"<li>{CODE}ls</code></li>" in section
    assert "<pre" not in section


def test_writes_a_code_block_as_pre_code_without_backticks():
    rule = 'rule X {\n  strings:\n    $a = "y"\n  condition:\n    $a\n}'
    article = extract_article(
        RSS_REFERENCE["url"],
        _post(
            f"<pre><code>{rule}</code></pre><pre><code>Get-Process\nStop-Process</code></pre>"
        ),
    )
    blocks = [unescape(block) for block in _code_blocks(article.html)]
    assert blocks == [rule, "Get-Process\nStop-Process"]
    assert "`" not in _section(article.html)


def test_keeps_the_backticks_of_the_code_itself():
    article = extract_article(
        RSS_REFERENCE["url"],
        _post(
            "<pre><code>echo `whoami` &gt; out\ncat out</code></pre>"
            "<p>run <code>echo `id`</code> now</p>"
        ),
    )
    assert _code_blocks(article.html) == ["echo `whoami` &gt; out\ncat out"]
    assert f"<p>run {CODE}echo `id`</code> now</p>" in article.html


@pytest.mark.parametrize(
    "markup, code",
    [
        ("<pre>```yara\nrule X {\n}\n```</pre>", "rule X {\n}"),
        ("<pre><pre>```\nselect 1\nselect 2\n```</pre></pre>", "select 1\nselect 2"),
        ("<pre>`rule X { condition: true }`</pre>", "rule X { condition: true }"),
        ("<pre>``rule `X` {}``</pre>", "rule `X` {}"),
        ("<pre>```\nrule <b>X</b>\n```</pre>", "rule X"),
    ],
)
def test_drops_the_backtick_fence_around_a_code_block(markup, code):
    tree = lxml.html.fromstring(f"<div><h2>Code</h2>{markup}</div>")
    _restore_code_elements(tree)
    blocks = tree.xpath("//pre")
    assert len(blocks) == 1 and [child.tag for child in blocks[0]] == ["code"]
    assert blocks[0][0].text_content() == code


@pytest.mark.parametrize(
    "text",
    ["echo `id`", "`a` and `b`", "x = 1 # `", "``", "`"],
)
def test_keeps_backticks_that_do_not_fence_the_whole_code(text):
    tree = lxml.html.fromstring(f"<div><h2>Code</h2><pre>{text}\nline 2</pre></div>")
    _restore_code_elements(tree)
    assert tree.xpath("//pre/code")[0].text == f"{text}\nline 2"


def test_reads_a_deeply_nested_code_cell_without_recursion():
    """A code cell nested deeper than the recursion limit is still read."""
    cell = lxml.html.Element("td")
    node = lxml.etree.SubElement(cell, "div")
    for _ in range(sys.getrecursionlimit() * 2):
        node = lxml.etree.SubElement(node, "span")
    node.text = "select 1"
    lxml.etree.SubElement(cell, "div").text = "select 2"
    assert _code_lines(cell) == ["select 1", "select 2"]


# The shape of an Adobe AEM blog post: the article is a run of sibling
# div.text blocks, each holding one div.cmp-text, with figures between them,
# under the page's menus, related posts and footer.
AEM_URL = "https://www.example.com/en-us/blog/akira-ransomware-vpn-appliances/"


def _aem_block(index: int, paragraphs: int) -> str:
    return (
        '<div class="text text--blog-content">'
        f'<div class="cmp-text" id="text-{index:04d}" data-cmp-name="cmp-text-">'
        '<span style=" ">'
        + (f"<h2>Part {index}</h2>" if index else "")
        + "".join(
            f"<p>Block {index} paragraph {i}: the operators reused the VPN "
            "appliance access to stage their tooling before encryption.</p>"
            for i in range(paragraphs)
        )
        + "</span></div></div>"
    )


def _aem_page(sizes: list[int]) -> str:
    figures = (
        '<div class="image"><div class="cmp-image"><img src="https://cdn.example/f.png"'
        ' alt="Figure"><span class="cmp-image__title">Figure of the part</span>'
        "</div></div>"
    )
    menu = "".join(
        f'<li><a href="/en-us/blog/post-{i}/">Another post number {i} of the blog'
        "</a> Nov 0{i % 9 + 1}, 2026</li>"
        for i in range(40)
    )
    related = "".join(
        f'<div class="card"><a href="/en-us/blog/related-{i}/">Related post {i}'
        "</a><p>Short teaser of a related post.</p></div>"
        for i in range(3)
    )
    blocks = figures.join(_aem_block(i, size) for i, size in enumerate(sizes))
    return (
        f"<html><head><title>{NAME}</title></head><body>"
        f'<header><nav><ul class="menu">{menu}</ul></nav></header>'
        '<main><div class="aem-Grid">'
        f'<div class="headline"><h1>{NAME}</h1><p>November 04, 2026</p></div>'
        f'<div class="container-wp"><div class="cmp-container-wp">{blocks}</div></div>'
        f'<div class="relatedcontent">{related}</div>'
        "</div></main><footer><p>Copyright 2026. Privacy. Contact us.</p>"
        "</footer></body></html>"
    )


@pytest.mark.parametrize("sizes", [[4, 3, 9, 7], [10, 6, 5]])
def test_keeps_every_block_of_an_article_split_across_siblings(sizes):
    article = extract_article(AEM_URL, _aem_page(sizes))
    starts = [article.text.find(f"Block {i} paragraph 0:") for i in range(len(sizes))]
    assert -1 not in starts, starts
    assert starts == sorted(starts)
    last = len(sizes) - 1
    assert f"Block {last} paragraph {sizes[last] - 1}:" in article.text
    assert "cmp-text" not in article.html
    assert "data-report-article-body" not in article.html
    assert ' id="' not in article.html and " class=" not in article.html
    assert "Another post number" not in article.text
    assert judge(article, NAME, "", 500, 1.5, 0.6).accepted


def test_leaves_a_single_block_article_unchanged():
    page = _aem_page([12])
    article = extract_article(AEM_URL, page)
    assert article.body_length == 0
    assert "Block 0 paragraph 11:" in article.text


def test_refuses_an_extraction_that_kept_part_of_the_article_body():
    article = _article("word " * 400)
    article.body_length = 5000
    verdict = judge(article, NAME, "", 500, 1.5, 0.6)
    assert not verdict.accepted
    assert "partial article" in verdict.reason


def test_retries_on_the_article_body_when_the_extraction_is_partial(monkeypatch):
    from connector import article as module

    extract = module._extract
    calls = []

    def first_partial(html, url):
        calls.append(html)
        document = extract(html, url)
        if len(calls) == 1:
            # Keep the first paragraph only, as trafilatura did on such pages
            for paragraph in list(document.body.iter("p"))[1:]:
                paragraph.getparent().remove(paragraph)
        return document

    monkeypatch.setattr(module, "_extract", first_partial)
    article = extract_article(AEM_URL, _aem_page([4, 3, 9, 7]))
    assert len(calls) == 2
    assert "Block 3 paragraph 6:" in article.text
    assert article.title == NAME


def test_refuses_a_connection_that_lands_on_an_internal_address(monkeypatch):
    """DNS rebinding: the check before the request passed, the socket did not."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>internal</body></html>")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr("connector.article.check_public_url", lambda url: None)
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("http_proxy", raising=False)
    try:
        with pytest.raises(FetchError, match="non-public"):
            fetch_html(f"http://127.0.0.1:{server.server_port}/", "test", 5, 1000)
    finally:
        server.shutdown()


PAID = (
    "https://ads.example.net/lp?utm_source=display_network&amp;utm_medium=paid_display"
)
PARTNER = "https://partner.example.org/post?utm_source=blog&amp;utm_medium=3rd-party"


@pytest.mark.parametrize(
    ("href", "paid"),
    [
        ("https://a.example/?utm_medium=paid_display", True),
        ("https://a.example/?utm_medium=paid_social&utm_source=x", True),
        ("https://a.example/?utm_medium=Paid", True),
        ("https://a.example/?utm_source=display_network", True),
        ("https://a.example/?utm_medium=3rd-party", False),
        ("https://a.example/?utm_medium=referral", False),
        ("https://a.example/?utm_source=blog&utm_medium=display", False),
        ("https://a.example/paid_display", False),
        ("", False),
        (None, False),
    ],
)
def test_tells_paid_advertising_links(href, paid):
    assert _is_paid_link(href) is paid


def _ad_post(ad: str, closing: str = "Closing words of the article.") -> str:
    return (
        f"<html><head><title>{NAME}</title></head><body><article><h1>{NAME}</h1>"
        + "".join(
            f"<p>Paragraph {i} of the report on the ransomware campaign.</p>"
            for i in range(20)
        )
        + f"<p>{closing}</p>{ad}</article></body></html>"
    )


def test_drops_a_paid_ad_callout_inside_the_article():
    ad = (
        f'<div class="callout"><div class="media"><a href="{PAID}"></a></div>'
        f'<div class="text"><h2><a href="{PAID}">Try our scanner today.</a></h2>'
        "<p>Our agents find what your tools miss.</p>"
        f'<a class="cta" href="{PAID}">Start your free scan.</a></div></div>'
    )
    article = extract_article(RSS_REFERENCE["url"], _ad_post(ad))
    assert "Try our scanner" not in article.text
    assert "Our agents find" not in article.text
    assert "Start your free scan" not in article.text
    assert "ads.example.net" not in article.html
    assert article.text.rstrip().endswith("Closing words of the article.")
    assert all(f"Paragraph {i} of the report" in article.text for i in range(20))


def test_drops_a_paid_heading_and_its_promo_siblings_without_a_container():
    ad = (
        f'<h2><a href="{PAID}">Try our scanner today.</a></h2>'
        "<p>Our agents find what your tools miss.</p>"
        f'<p><a href="{PAID}">Start your free scan.</a></p>'
        "<p>Last words written by the author.</p>"
    )
    html = _ad_post("").replace(
        "<p>Closing words of the article.</p>",
        f"<p>Closing words of the article.</p>{ad}",
    )
    article = extract_article(RSS_REFERENCE["url"], html)
    assert "Try our scanner" not in article.text
    assert "Our agents find" not in article.text
    assert "Start your free scan" not in article.text
    assert "Last words written by the author." in article.text


def test_keeps_a_paragraph_with_a_non_paid_tracked_link():
    closing = f'Read the <a href="{PARTNER}">partner analysis</a> of the loader.'
    article = extract_article(RSS_REFERENCE["url"], _ad_post("", closing))
    assert "partner analysis" in article.text
    assert "partner.example.org/post?utm_source=blog" in article.html


def test_keeps_an_article_paragraph_that_holds_a_paid_link():
    closing = (
        "The loader was spread through a malvertising campaign that bought "
        f'<a href="{PAID}">this display ad</a> on several news sites.'
    )
    article = extract_article(RSS_REFERENCE["url"], _ad_post("", closing))
    assert "malvertising campaign" in article.text
    assert "on several news sites." in article.text
