"""Test module for ClientAPIIndicator."""

import io
import json
import tarfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from connector.src.custom.client_api.indicator.client_api_indicator import (
    ClientAPIIndicator,
)

# =====================
# Helpers
# =====================


def _make_tar_bz2(files: dict[str, str]) -> bytes:
    """Create a tar.bz2 archive from a dict of {filename: content}."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:bz2") as tar:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_tar_bz2_with_directory(files: dict[str, str], dirs: list[str]) -> bytes:
    """Create a tar.bz2 with both files and directory entries."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:bz2") as tar:
        for dir_name in dirs:
            info = tarfile.TarInfo(name=dir_name)
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# =====================
# Fixtures
# =====================


@pytest.fixture
def mock_fetcher() -> MagicMock:
    """A mock fetcher with an async fetch_bytes method."""
    fetcher = MagicMock()
    fetcher.fetch_bytes = AsyncMock()
    return fetcher


@pytest.fixture
def mock_fetcher_factory(mock_fetcher: MagicMock) -> MagicMock:
    """A mock fetcher factory that returns the mock fetcher."""
    factory = MagicMock()
    factory.create_fetcher_by_name.return_value = mock_fetcher
    return factory


@pytest.fixture
def client(mock_fetcher_factory: MagicMock) -> ClientAPIIndicator:
    """ClientAPIIndicator with mocked dependencies."""
    config = SimpleNamespace(
        api_url=SimpleNamespace(unicode_string=lambda: "https://api.example.com")
    )
    return ClientAPIIndicator(
        config=config,
        logger=MagicMock(),
        api_client=MagicMock(),
        fetcher_factory=mock_fetcher_factory,
    )


# =====================
# Scenario: fetch_ioc_delta_package – HTTP 200
# =====================


@pytest.mark.asyncio
async def test_fetch_ioc_delta_package_200_returns_parsed_entries(
    client: ClientAPIIndicator,
    mock_fetcher: MagicMock,
) -> None:
    """200 OK returns parsed NDJSON entries from the tar.bz2 payload."""
    # Given
    entries = [
        {"type": "domain", "value": "evil.com"},
        {"type": "ip", "value": "1.2.3.4"},
    ]
    ndjson = "\n".join(json.dumps(e) for e in entries)
    tar_bytes = _make_tar_bz2({"iocs.ndjson": ndjson})
    mock_fetcher.fetch_bytes.return_value = (200, tar_bytes)

    # When
    result = await client.fetch_ioc_delta_package("pkg-1", "domain")

    # Then
    assert result == entries


# =====================
# Scenario: fetch_ioc_delta_package – HTTP 404
# =====================


@pytest.mark.asyncio
async def test_fetch_ioc_delta_package_404_returns_none(
    client: ClientAPIIndicator,
    mock_fetcher: MagicMock,
) -> None:
    """404 Not Found returns None."""
    # Given
    mock_fetcher.fetch_bytes.return_value = (404, b"")

    # When
    result = await client.fetch_ioc_delta_package("pkg-missing", "ip")

    # Then
    assert result is None


# =====================
# Scenario: fetch_ioc_delta_package – HTTP 400
# =====================


@pytest.mark.asyncio
async def test_fetch_ioc_delta_package_400_returns_none(
    client: ClientAPIIndicator,
    mock_fetcher: MagicMock,
) -> None:
    """400 Bad Request (package not available yet) returns None."""
    # Given
    mock_fetcher.fetch_bytes.return_value = (400, b"Package not ready")

    # When
    result = await client.fetch_ioc_delta_package("pkg-pending", "url")

    # Then
    assert result is None


# =====================
# Scenario: fetch_ioc_delta_package – unexpected status (500)
# =====================


@pytest.mark.asyncio
async def test_fetch_ioc_delta_package_unexpected_status_returns_none(
    client: ClientAPIIndicator,
    mock_fetcher: MagicMock,
) -> None:
    """Unexpected HTTP status (e.g. 500) returns None and logs a warning."""
    # Given
    mock_fetcher.fetch_bytes.return_value = (500, b"Internal Server Error")

    # When
    result = await client.fetch_ioc_delta_package("pkg-err", "file")

    # Then
    assert result is None
    client.logger.warning.assert_called_once()


# =====================
# Scenario: _parse_tar_bz2 – valid archive
# =====================


def test_parse_tar_bz2_valid_archive(client: ClientAPIIndicator) -> None:
    """Valid tar.bz2 with NDJSON returns all parsed objects."""
    # Given
    entries = [{"id": 1}, {"id": 2}, {"id": 3}]
    ndjson = "\n".join(json.dumps(e) for e in entries)
    tar_bytes = _make_tar_bz2({"data.ndjson": ndjson})

    # When
    result = client._parse_tar_bz2(tar_bytes, "pkg-ok", "domain")

    # Then
    assert result == entries


# =====================
# Scenario: _parse_tar_bz2 – multiple files
# =====================


def test_parse_tar_bz2_multiple_files(client: ClientAPIIndicator) -> None:
    """Multiple NDJSON files in the archive are all parsed."""
    # Given
    tar_bytes = _make_tar_bz2(
        {
            "a.ndjson": json.dumps({"file": "a"}),
            "b.ndjson": json.dumps({"file": "b"}),
        }
    )

    # When
    result = client._parse_tar_bz2(tar_bytes, "pkg-multi", "ip")

    # Then
    assert result == [{"file": "a"}, {"file": "b"}]


# =====================
# Scenario: _parse_tar_bz2 – invalid archive
# =====================


def test_parse_tar_bz2_invalid_archive_returns_empty(
    client: ClientAPIIndicator,
) -> None:
    """Invalid tar.bz2 content triggers TarError and returns []."""
    # Given
    bad_content = b"this is not a tar.bz2 file"

    # When
    result = client._parse_tar_bz2(bad_content, "pkg-bad", "domain")

    # Then
    assert result == []
    client.logger.warning.assert_called_once()


# =====================
# Scenario: _parse_tar_bz2 – invalid JSON line
# =====================


def test_parse_tar_bz2_skips_invalid_json_keeps_valid(
    client: ClientAPIIndicator,
) -> None:
    """Invalid JSON lines are skipped; valid lines are kept."""
    # Given
    content = (
        json.dumps({"valid": True})
        + "\n{broken json\n"
        + json.dumps({"also_valid": True})
    )
    tar_bytes = _make_tar_bz2({"mixed.ndjson": content})

    # When
    result = client._parse_tar_bz2(tar_bytes, "pkg-mixed", "url")

    # Then
    assert result == [{"valid": True}, {"also_valid": True}]
    client.logger.debug.assert_called()


# =====================
# Scenario: _parse_tar_bz2 – empty and whitespace lines
# =====================


def test_parse_tar_bz2_skips_empty_and_whitespace_lines(
    client: ClientAPIIndicator,
) -> None:
    """Empty lines and whitespace-only lines are silently skipped."""
    # Given
    content = "\n  \n" + json.dumps({"ok": 1}) + "\n\n   \n"
    tar_bytes = _make_tar_bz2({"sparse.ndjson": content})

    # When
    result = client._parse_tar_bz2(tar_bytes, "pkg-sparse", "ip")

    # Then
    assert result == [{"ok": 1}]


# =====================
# Scenario: _parse_tar_bz2 – directory members are skipped
# =====================


def test_parse_tar_bz2_skips_directory_members(client: ClientAPIIndicator) -> None:
    """Directory entries in the archive are skipped."""
    # Given
    tar_bytes = _make_tar_bz2_with_directory(
        files={"data/file.ndjson": json.dumps({"found": True})},
        dirs=["data/"],
    )

    # When
    result = client._parse_tar_bz2(tar_bytes, "pkg-dir", "domain")

    # Then
    assert result == [{"found": True}]
