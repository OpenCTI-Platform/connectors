"""fetch_html against a local server, and the helpers around it."""

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from connector import article as article_module
from connector.article import (
    Article,
    FetchError,
    _decode,
    _prepare,
    _strip_document,
    article_match,
    check_public_url,
    fetch_html,
)

PAGE = b"<html><head><title>Post</title></head><body><p>Article</p></body></html>"

# path -> (status, headers, body)
ROUTES = {
    "/page": (200, {"Content-Type": "text/html; charset=utf-8"}, PAGE),
    "/hop1": (301, {"Location": "/hop2"}, b""),
    "/hop2": (302, {"Location": "/page"}, b""),
    "/no-location": (302, {}, b""),
    "/empty-location": (302, {"Location": " "}, b""),
    "/loop": (302, {"Location": "/loop"}, b""),
    "/missing": (404, {"Content-Type": "text/html"}, b"not found"),
    "/pdf": (200, {"Content-Type": "application/pdf"}, b"%PDF"),
    "/untyped": (200, {}, b"<html></html>"),
    "/big": (200, {"Content-Type": "text/html"}, b"<p>" + b"x" * 5000 + b"</p>"),
    "/refresh": (
        200,
        {"Content-Type": "text/html"},
        b'<html><head><meta http-equiv="refresh" content="0;URL=\'/page\'">'
        b"</head></html>",
    ),
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/big-streamed":
            # No Content-Length: the size is only known while reading
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"<p>" + b"x" * 5000 + b"</p>")
            return
        status, headers, body = ROUTES[self.path]
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


@pytest.fixture
def checked(monkeypatch):
    """Let the connector reach the local server; record every URL checked."""
    urls = []
    monkeypatch.setattr(article_module, "check_public_url", urls.append)
    monkeypatch.setattr(article_module, "_is_public", lambda address: True)
    for name in ("HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    return urls


def _fetch(url, max_size=10_000):
    return fetch_html(url, user_agent="test", timeout=5, max_size=max_size)


def test_fetches_an_html_page(server, checked):
    assert _fetch(f"{server}/page") == (f"{server}/page", PAGE.decode())


def test_checks_every_hop_of_a_redirect_chain(server, checked):
    final_url, html = _fetch(f"{server}/hop1")
    assert final_url == f"{server}/page"
    assert html == PAGE.decode()
    assert checked == [f"{server}/hop1", f"{server}/hop2", f"{server}/page"]


@pytest.mark.parametrize("path", ["/no-location", "/empty-location"])
def test_refuses_a_redirect_without_location(server, checked, path):
    with pytest.raises(FetchError, match="Redirect without Location"):
        _fetch(f"{server}{path}")


def test_stops_a_redirect_loop(server, checked):
    with pytest.raises(FetchError, match="Too many redirects"):
        _fetch(f"{server}/loop")
    assert len(checked) == 6


def test_refuses_a_redirect_to_an_internal_address(server, monkeypatch):
    def check(url):
        if url.endswith("/hop2"):
            raise FetchError("internal.example resolves to a non-public address")

    monkeypatch.setattr(article_module, "check_public_url", check)
    monkeypatch.setattr(article_module, "_is_public", lambda address: True)
    with pytest.raises(FetchError, match="non-public"):
        _fetch(f"{server}/hop1")


def test_refuses_an_error_status(server, checked):
    with pytest.raises(FetchError, match="HTTP 404"):
        _fetch(f"{server}/missing")


@pytest.mark.parametrize(
    "path,reason", [("/pdf", "application/pdf"), ("/untyped", "unknown")]
)
def test_refuses_a_page_that_is_not_html(server, checked, path, reason):
    with pytest.raises(FetchError, match=f"Not an HTML page: {reason}"):
        _fetch(f"{server}{path}")


@pytest.mark.parametrize("path", ["/big", "/big-streamed"])
def test_refuses_a_page_too_large(server, checked, path):
    with pytest.raises(FetchError, match="larger than 1000 bytes"):
        _fetch(f"{server}{path}", max_size=1000)


def test_follows_a_meta_refresh_stub(server, checked):
    final_url, html = _fetch(f"{server}/refresh")
    assert final_url == f"{server}/page"
    assert html == PAGE.decode()


def test_a_connection_error_is_a_fetch_error(checked):
    with pytest.raises(FetchError, match="Request failed"):
        _fetch("http://127.0.0.1:1/")


def test_refuses_an_invalid_port():
    with pytest.raises(FetchError, match="Invalid port"):
        check_public_url("http://example.com:99999/post")


def test_refuses_a_host_that_does_not_resolve(monkeypatch):
    def fail(*_):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(FetchError, match="Cannot resolve"):
        check_public_url("https://nowhere.example/post")


def test_accepts_a_public_address(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_: [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 443))],
    )
    check_public_url("https://example.com:443/post")


def test_refuses_an_ipv4_mapped_internal_address(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_: [(socket.AF_INET6, 0, 0, "", ("::ffff:10.0.0.1", 0, 0, 0))],
    )
    with pytest.raises(FetchError, match="non-public"):
        check_public_url("https://mapped.example/post")


def test_decodes_with_the_header_charset():
    assert _decode("é".encode("latin-1"), "text/html; charset=iso-8859-1") == "é"


def test_decodes_with_the_meta_charset():
    body = '<meta charset="windows-1252"><p>é</p>'.encode("cp1252")
    assert _decode(body, "text/html").endswith("<p>é</p>")


def test_decodes_utf8_by_default():
    assert _decode("é".encode(), "text/html") == "é"


def test_an_unknown_charset_falls_back_to_utf8():
    assert _decode("é".encode(), "text/html; charset=no-such-charset") == "é"


def test_prepare_leaves_unparsable_input_alone():
    assert _prepare("") == ""


def test_prepare_leaves_a_page_with_nothing_to_rework_alone():
    html = "<html><body><p>Plain article</p></body></html>"
    assert _prepare(html) == html


def test_strip_document_keeps_the_body_inside():
    assert _strip_document("<html><body class='x'> <p>a</p> </body></html>") == (
        "<p>a</p>"
    )
    assert _strip_document(" <p>a</p> ") == "<p>a</p>"


def test_a_generic_page_title_is_not_a_match():
    article = Article(
        url="https://example.com/news", title="Ransomware", html="", text=""
    )
    assert article_match("Akira ransomware targets VPN appliances", article) < 0.6


def test_a_page_title_inside_the_report_name_is_a_match():
    article = Article(
        url="https://example.com/p/1",
        title="Akira ransomware targets VPN",
        html="",
        text="",
    )
    assert article_match("Akira ransomware targets VPN appliances", article) == 1.0


def test_an_empty_report_name_matches_nothing():
    article = Article(url="https://example.com/a", title="Title", html="", text="")
    assert article_match("", article) == 0.0
    assert article_match("!!!", article) == 0.0
