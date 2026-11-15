import re
import socket
import threading
from html import unescape
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from connector.article import (
    Article,
    FetchError,
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


def _code_blocks(html: str) -> list[str]:
    return re.findall(r"<pre><code>(.*?)</code></pre>", html, re.DOTALL)


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
