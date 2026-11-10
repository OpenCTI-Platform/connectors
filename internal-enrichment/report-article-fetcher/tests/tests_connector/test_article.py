import socket
import threading
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
