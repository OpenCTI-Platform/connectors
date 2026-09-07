import asyncio
import importlib.util
import os
from typing import Any

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
