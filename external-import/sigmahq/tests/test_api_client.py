"""Regression tests for the ZIP-extraction layer of ``SigmaHQClient``.

The pipeline is download (one HTTP GET) → unzip in memory → decode each
``.yml`` member as UTF-8. The decode step is the brittle part: a single
malformed (non-UTF-8) file inside the archive used to raise
``UnicodeDecodeError`` and bubble out to the outer ``except`` — dropping
the whole package even though every other rule in the archive was
valid. The per-file decode guard added in this PR replaces that
all-or-nothing behaviour with "skip the bad file, log a warning,
continue".

These tests pin the contract by feeding the client an in-memory ZIP
crafted to carry a mix of valid UTF-8 rules + one non-UTF-8 file +
one ``.yaml`` (non-``.yml`` extension, expected to be ignored) +
one folder entry.
"""

import zipfile
from io import BytesIO
from unittest.mock import MagicMock, patch

from sigmahq_client.api_client import SigmaHQClient


def _build_archive(members: dict[str, bytes]) -> bytes:
    """Return the raw bytes of a ZIP containing the given members."""
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in members.items():
            zf.writestr(name, payload)
    return buffer.getvalue()


def _make_client() -> SigmaHQClient:
    return SigmaHQClient(helper=MagicMock())


def test_download_and_convert_skips_non_utf8_rule_and_keeps_others():
    """A single non-UTF-8 ``.yml`` must not drop every other rule."""
    archive = _build_archive(
        {
            "rules/valid_a.yml": b"title: A\nid: 0\nlogsource:\n  product: x\n",
            # 0xFF / 0xFE are not legal UTF-8 lead bytes — guaranteed
            # to raise ``UnicodeDecodeError`` when decoded as UTF-8.
            "rules/bad.yml": b"title: B\nbody: \xff\xfe garbage\n",
            "rules/valid_b.yml": b"title: C\nid: 1\nlogsource:\n  product: x\n",
            # folder entry — ignored by the loop.
            "rules/": b"",
            # non-``.yml`` extension — ignored by the loop.
            "rules/notes.yaml": b"title: D\n",
        }
    )

    client = _make_client()
    fake_response = MagicMock()
    fake_response.content = archive
    fake_response.raise_for_status = MagicMock()
    with patch.object(client.session, "get", return_value=fake_response) as get_mock:
        rules = client.download_and_convert_package(
            "https://example.invalid/sigma_core.zip"
        )

    get_mock.assert_called_once()
    filenames = sorted(rule["filename"] for rule in rules)
    assert filenames == ["rules/valid_a.yml", "rules/valid_b.yml"]
    # A clean per-file warning surfaces in the connector log (not an
    # error — the run is still successful, one rule is just dropped).
    client.helper.connector_logger.warning.assert_called_once()
    warn_args = client.helper.connector_logger.warning.call_args
    assert "rules/bad.yml" in str(warn_args)


def test_download_and_convert_returns_empty_list_on_http_failure():
    """HTTP-level errors return ``[]`` and are logged as ``error``."""
    client = _make_client()
    with patch.object(
        client.session,
        "get",
        side_effect=RuntimeError("connection reset"),
    ):
        rules = client.download_and_convert_package(
            "https://example.invalid/sigma_core.zip"
        )

    assert rules == []
    client.helper.connector_logger.error.assert_called_once()
