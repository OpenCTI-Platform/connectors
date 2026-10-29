import asyncio
import http.server
import importlib.util
import os
import threading
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pdfminer.pdfparser import PDFSyntaxError
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings

# The connector's entrypoint module uses a hyphenated filename
# ("import-external-reference.py") which is not a valid Python identifier,
# so it cannot be imported with a regular `import` statement. We load it
# explicitly by file path instead.
_MAIN_PATH = os.path.join(
    os.path.dirname(__file__), "..", "src", "import-external-reference.py"
)
_spec = importlib.util.spec_from_file_location(
    "import_external_reference_main", _MAIN_PATH
)
main_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(main_module)

ImportExternalReferenceConnector = main_module.ImportExternalReferenceConnector


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "ImportExternalReference",
                    "scope": "External-Reference",
                    "log_level": "error",
                    "auto": False,
                },
                "import_external_reference": {
                    "import_as_pdf": True,
                    "import_as_md": True,
                    "import_pdf_as_md": True,
                    "timestamp_files": False,
                    "cache_size": 32,
                    "cache_ttl": 3600,
                    "browser_worker_count": 4,
                    "max_download_size": 52428800,
                },
            }
        )


def test_connector_settings_is_instantiated():
    """
    Test that the implementation of `BaseConnectorSettings` (from `connectors-sdk`) can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from `BaseConnectorSettings`)
        - the method `to_helper_config` MUST return a dict (as in base class)
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that `OpenCTIConnectorHelper` (from `pycti`) can be instantiated successfully:
        - the value of `settings.to_helper_config` MUST be the expected dict for `OpenCTIConnectorHelper`
        - the helper MUST be able to get its instance's attributes from the config dict
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "ImportExternalReference"
    assert helper.connect_scope == "External-Reference"
    assert helper.log_level == "ERROR"
    assert helper.connect_auto is False


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the connector's main class can be instantiated successfully.

    The `ImportExternalReferenceConnector` builds its own configuration and
    helper internally (via `ConnectorSettings`). We patch `ConnectorSettings`
    where the connector looks it up so the connector uses the stubbed config:
        - the connector's main class MUST be able to access env/config vars through `self.config`
        - the connector's main class MUST be able to access `pycti` API through `self.helper`
    """
    monkeypatch.setattr(main_module, "ConnectorSettings", StubConnectorSettings)

    connector = ImportExternalReferenceConnector()

    assert isinstance(connector.config, ConnectorSettings)
    assert connector.helper is not None
    assert connector.import_as_pdf is True
    assert connector.import_as_md is True
    assert connector.import_pdf_as_md is True
    assert connector.timestamp_files is False
    assert connector.cache_size == 32
    assert connector.cache_ttl == 3600
    assert connector.worker_count == 4
    assert connector.max_download_size == 52428800


@pytest.fixture
def connector(mock_opencti_connector_helper, monkeypatch):
    """Build a connector instance on the stubbed settings, with the OpenCTI API mocked."""
    monkeypatch.setattr(main_module, "ConnectorSettings", StubConnectorSettings)
    return ImportExternalReferenceConnector()


def _build_minimal_pdf(text: str) -> bytes:
    """
    Build the smallest valid single-page PDF that renders `text` with a standard font.

    The xref table offsets are computed so that pdfminer parses the file without
    falling back to its damaged-file recovery path.
    """
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += b"%d 0 obj\n" % number + body + b"\nendobj\n"

    xref_offset = len(pdf)
    pdf += b"xref\n0 %d\n" % (len(objects) + 1)
    pdf += b"0000000000 65535 f \n"
    for offset in offsets:
        pdf += b"%010d 00000 n \n" % offset
    pdf += b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (len(objects) + 1)
    pdf += b"startxref\n%d\n%%%%EOF\n" % xref_offset
    return bytes(pdf)


def test_html_to_markdown(connector):
    """
    Test that `_html_to_markdown` converts HTML to Markdown with the options that
    preserve the pre-migration (html2text) output shape:
        - headings MUST use the ATX style (`#`)
        - a headerless table MUST keep its first row as the header
        - links MUST be kept inline
    """
    html = (
        "<h2>Summary</h2>"
        "<table><tr><td>a</td><td>b</td></tr><tr><td>c</td><td>d</td></tr></table>"
        '<p><a href="https://example.com/x">link</a></p>'
    )

    markdown = connector._html_to_markdown(html)

    assert "## Summary" in markdown
    assert "| a | b |" in markdown
    assert "| --- | --- |" in markdown
    assert "| c | d |" in markdown
    assert "[link](https://example.com/x)" in markdown


def test_pdf_to_html_sync_extracts_text(connector):
    """
    Test that `_pdf_to_html_sync` converts a PDF into HTML containing its text.
    This is the path that used to fail on every call because `HTMLConverter`
    was built without `codec=None` for a text output stream.
    """
    html = connector._pdf_to_html_sync(_build_minimal_pdf("Hello from PDF"))

    assert "<html>" in html
    assert "Hello from PDF" in html


def test_pdf_to_html_sync_closes_resources_on_corrupt_pdf(connector, monkeypatch):
    """
    Test that `_pdf_to_html_sync` re-raises the parser error on a corrupt PDF and
    still closes the converter, which the previous implementation skipped.
    """
    closed = []

    class SpyHTMLConverter(main_module.HTMLConverter):
        def close(self):
            closed.append(True)
            return super().close()

    monkeypatch.setattr(main_module, "HTMLConverter", SpyHTMLConverter)

    with pytest.raises(PDFSyntaxError):
        connector._pdf_to_html_sync(b"%PDF-1.4\nthis is not a pdf")

    assert closed == [True]


def test_process_external_reference_attaches_markdown_from_html(connector, monkeypatch):
    """
    Test the HTML → Markdown import path of `_process_external_reference`:
        - the page fetched by the browser MUST be converted to Markdown
        - protocol-relative links MUST be made absolute
        - the result MUST be attached to the external reference as a `.md` file
    """
    connector.import_as_pdf = False

    async def fake_fetch_with_browser(url, timeout=180):
        return (
            '<h1>Report</h1><p><a href="//cdn.example/asset">asset</a></p>',
            None,
        )

    monkeypatch.setattr(connector, "_fetch_with_browser", fake_fetch_with_browser)

    result = asyncio.run(
        connector._process_external_reference(
            {"id": "external-reference--1", "url": "https://example.com/report"}
        )
    )

    assert result == "Import complete."
    add_file = connector.helper.api.external_reference.add_file
    add_file.assert_called_once()
    kwargs = add_file.call_args.kwargs
    assert kwargs["id"] == "external-reference--1"
    assert kwargs["file_name"] == "report.md"
    assert kwargs["mime_type"] == "text/markdown"
    assert "# Report" in kwargs["data"]
    assert "[asset](https://cdn.example/asset)" in kwargs["data"]


def test_process_external_reference_attaches_markdown_from_pdf(connector, monkeypatch):
    """
    Test the PDF → HTML → Markdown import path of `_process_external_reference`:
        - the downloaded PDF MUST be converted to Markdown
        - the result MUST be attached to the external reference as a `.md` file
    Before the fix this path silently produced nothing (the conversion errors were
    caught and only logged).
    """
    connector.import_as_pdf = False

    async def fake_download_url(url):
        return _build_minimal_pdf("Hello from PDF")

    monkeypatch.setattr(connector, "_download_url", fake_download_url)

    result = asyncio.run(
        connector._process_external_reference(
            {"id": "external-reference--2", "url": "https://example.com/report.pdf"}
        )
    )

    assert result == "Import complete."
    add_file = connector.helper.api.external_reference.add_file
    add_file.assert_called_once()
    kwargs = add_file.call_args.kwargs
    assert kwargs["id"] == "external-reference--2"
    assert kwargs["file_name"] == "report.pdf.md"
    assert kwargs["mime_type"] == "text/markdown"
    assert "Hello from PDF" in kwargs["data"]


@pytest.fixture
def http_server():
    """Serve a few canned responses on a local port, recording the request headers."""
    received = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            received[self.path] = self.headers
            if self.path == "/old":
                self.send_response(301)
                self.send_header("Location", "/new")
                self.end_headers()
            elif self.path == "/new":
                body = b"<html>new</html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Set-Cookie", "a=1")
                self.send_header("Set-Cookie", "b=2")
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", received
    server.shutdown()
    server.server_close()


def test_fetch_for_browser_sync_follows_redirects(connector, http_server):
    """
    Test that `_fetch_for_browser_sync` returns the response a redirect leads to,
    in the shape `route.fulfill` takes:
        - the final URL MUST be the one of the redirect target
        - repeated Set-Cookie headers MUST be joined by newlines
        - the headers describing the transfer MUST be dropped
        - the browser's Accept-Encoding MUST be replaced by the identity encoding
    """
    base_url, received = http_server

    url, status, headers, body = connector._fetch_for_browser_sync(
        "GET", f"{base_url}/old", {"accept-encoding": "gzip", "x-test": "1"}, None
    )

    assert url == f"{base_url}/new"
    assert status == 200
    assert body == b"<html>new</html>"
    assert headers["Set-Cookie"] == "a=1\nb=2"
    assert "Content-Length" not in headers
    assert received["/new"]["x-test"] == "1"
    assert received["/new"]["Accept-Encoding"] == "identity"


def test_fetch_for_browser_sync_returns_error_responses(connector, http_server):
    """
    Test that `_fetch_for_browser_sync` returns an HTTP error as a response for the
    browser to render, instead of raising it.
    """
    base_url, _ = http_server

    _, status, _, _ = connector._fetch_for_browser_sync(
        "GET", f"{base_url}/missing", {}, None
    )

    assert status == 404


def test_route_through_python_fulfills_navigation_from_prefetched(
    connector, monkeypatch
):
    """
    Test that `_route_through_python` fulfills the navigation to a prefetched page
    with the prefetched response, without fetching it again.
    """
    route = MagicMock(fulfill=AsyncMock(), abort=AsyncMock())
    request = MagicMock(
        url="https://example.com/new",
        resource_type="document",
        is_navigation_request=MagicMock(return_value=True),
    )
    prefetched = {
        "https://example.com/new": (
            "https://example.com/new",
            200,
            {"Content-Type": "text/html"},
            b"<html>new</html>",
        )
    }
    fetch = AsyncMock()
    monkeypatch.setattr(connector, "_fetch_for_browser", fetch)

    asyncio.run(connector._route_through_python(route, request, prefetched))

    fetch.assert_not_called()
    route.fulfill.assert_awaited_once_with(
        status=200, headers={"Content-Type": "text/html"}, body=b"<html>new</html>"
    )
    assert prefetched == {}


def test_route_through_python_aborts_failed_fetches(connector, monkeypatch):
    """
    Test that `_route_through_python` aborts a request whose fetch fails, instead of
    letting the browser send it itself.
    """
    route = MagicMock(fulfill=AsyncMock(), abort=AsyncMock())
    request = MagicMock(
        url="https://example.com/script.js",
        resource_type="script",
        is_navigation_request=MagicMock(return_value=False),
        all_headers=AsyncMock(return_value={}),
        post_data_buffer=None,
    )
    monkeypatch.setattr(
        connector, "_fetch_for_browser", AsyncMock(side_effect=OSError("refused"))
    )

    asyncio.run(connector._route_through_python(route, request, {}))

    route.abort.assert_awaited_once()
    route.fulfill.assert_not_called()


def test_fetch_for_browser_enforces_max_download_size(connector, http_server):
    """
    Test that `_fetch_for_browser` refuses a response larger than the maximum
    download size.
    """
    base_url, _ = http_server
    connector.max_download_size = 4

    with pytest.raises(ValueError, match="exceeds size limit"):
        asyncio.run(connector._fetch_for_browser("GET", f"{base_url}/new", {}, None))


def test_route_through_python_aborts_media(connector, monkeypatch):
    """
    Test that `_route_through_python` aborts media requests without fetching them.
    """
    route = MagicMock(fulfill=AsyncMock(), abort=AsyncMock())
    request = MagicMock(url="https://example.com/video.mp4", resource_type="media")
    fetch = AsyncMock()
    monkeypatch.setattr(connector, "_fetch_for_browser", fetch)

    asyncio.run(connector._route_through_python(route, request, {}))

    route.abort.assert_awaited_once()
    fetch.assert_not_called()


def test_init_async_launches_browser_off_the_network(connector, monkeypatch):
    """
    Test that, when the browser's requests are fetched from Python, `_init_async`
    launches the configured browser behind a proxy where nothing listens, loopback
    included, with non-proxied UDP disabled.
    """
    connector.fetch_from_python = True
    connector.chromium_executable_path = "/usr/bin/chromium-browser"
    playwright = MagicMock()
    playwright.chromium.launch = AsyncMock()
    monkeypatch.setattr(
        main_module,
        "async_playwright",
        MagicMock(return_value=MagicMock(start=AsyncMock(return_value=playwright))),
    )

    async def init():
        await connector._init_async()
        for worker in connector.workers:
            worker.cancel()

    asyncio.run(init())

    kwargs = playwright.chromium.launch.call_args.kwargs
    assert kwargs["executable_path"] == "/usr/bin/chromium-browser"
    assert kwargs["proxy"] == {"server": "http://127.0.0.1:9", "bypass": "<-loopback>"}
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in kwargs["args"]


def _run_browser_worker(connector, monkeypatch, url):
    """
    Run one task through `_browser_worker` on a mocked browser, and return its
    result and the mocked page.
    """

    async def no_sleep(_):
        return None

    monkeypatch.setattr(main_module.asyncio, "sleep", no_sleep)

    page = MagicMock(
        goto=AsyncMock(return_value=MagicMock(status=200)),
        route=AsyncMock(),
        wait_for_load_state=AsyncMock(),
        evaluate=AsyncMock(),
        content=AsyncMock(return_value="<html>new</html>"),
        pdf=AsyncMock(return_value=b"%PDF-1.4"),
        close=AsyncMock(),
        locator=MagicMock(return_value=MagicMock(count=AsyncMock(return_value=0))),
    )
    ctx = MagicMock(
        add_init_script=AsyncMock(),
        new_page=AsyncMock(return_value=page),
        close=AsyncMock(),
    )
    connector.browser = MagicMock(new_context=AsyncMock(return_value=ctx))

    async def run_worker():
        connector.task_queue = asyncio.Queue()
        future = asyncio.get_running_loop().create_future()
        await connector.task_queue.put((url, future))
        worker = asyncio.create_task(connector._browser_worker())
        result = await asyncio.wait_for(future, timeout=5)
        worker.cancel()
        return result

    return asyncio.run(run_worker()), page


def test_browser_worker_opens_the_page_redirects_lead_to(connector, monkeypatch):
    """
    Test that, when the browser's requests are fetched from Python, the browser
    worker follows the redirects of the page before the navigation:
        - the browser MUST open the URL the redirects lead to
        - the routes MUST fulfill that navigation with the prefetched response
        - service workers MUST be blocked
    """
    connector.fetch_from_python = True
    prefetched = ("https://example.com/new", 200, {}, b"<html>new</html>")
    fetch = AsyncMock(return_value=prefetched)
    monkeypatch.setattr(connector, "_fetch_for_browser", fetch)

    result, page = _run_browser_worker(connector, monkeypatch, "http://example.com/old")

    assert result == ("<html>new</html>", b"%PDF-1.4")
    fetch.assert_awaited_once_with(
        "GET", "http://example.com/old", connector.headers, None
    )
    page.goto.assert_awaited_once_with(
        "https://example.com/new", wait_until="domcontentloaded"
    )
    assert connector.browser.new_context.call_args.kwargs["service_workers"] == "block"

    route = MagicMock(fulfill=AsyncMock(), abort=AsyncMock())
    request = MagicMock(
        url="https://example.com/new",
        resource_type="document",
        is_navigation_request=MagicMock(return_value=True),
    )
    route_handler = page.route.call_args.args[1]
    asyncio.run(route_handler(route, request))
    route.fulfill.assert_awaited_once_with(
        status=200, headers={}, body=b"<html>new</html>"
    )
    fetch.assert_awaited_once()


def test_browser_worker_lets_the_browser_fetch_by_default(connector, monkeypatch):
    """
    Test that, by default, the browser worker lets the browser fetch the page
    itself: no prefetch, the requested URL opened, service workers allowed.
    """
    fetch = AsyncMock()
    monkeypatch.setattr(connector, "_fetch_for_browser", fetch)

    result, page = _run_browser_worker(
        connector, monkeypatch, "https://example.com/page"
    )

    assert result == ("<html>new</html>", b"%PDF-1.4")
    fetch.assert_not_called()
    page.goto.assert_awaited_once_with(
        "https://example.com/page", wait_until="domcontentloaded"
    )
    page.route.assert_awaited_once_with("**/*", connector._block_resource)
    assert connector.browser.new_context.call_args.kwargs["service_workers"] == "allow"
