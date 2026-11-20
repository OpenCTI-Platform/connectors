import hashlib
import io
from typing import Any

import pytest
import pyzipper
from connector.payloads_client import extract_sample, to_community_payload

BASE_URL = "https://api.spamhaus.com"


def _item(sha256: str = "a" * 64, **overrides: Any) -> dict[str, Any]:
    """Synthetic item shaped like `Payload` in the abuse.ch API reference."""
    item = {
        "file_name": "bin.exe",
        "file_size": 135784,
        "file_type": "exe",
        "first_seen": "2026-11-18T01:27:04Z",
        "last_seen": "2026-11-18T02:11:26Z",
        "md5_hash": "b" * 32,
        "sha256_hash": sha256,
        "signature": "Adwind",
        "urlhaus_download": f"{BASE_URL}/urlhaus/v1/files/samples/{sha256}",
    }
    item.update(overrides)
    return item


def test_to_community_payload_maps_the_spamhaus_item():
    payload = to_community_payload(_item("c" * 64))

    assert payload == {
        "sha256_hash": "c" * 64,
        "firstseen": "2026-11-18 01:27:04",
        "file_type": "exe",
        "signature": "Adwind",
        "urlhaus_download": f"{BASE_URL}/urlhaus/v1/files/samples/{'c' * 64}",
    }


def test_to_community_payload_defaults_a_missing_signature_to_none():
    item = _item()
    del item["signature"]

    assert to_community_payload(item)["signature"] is None


def test_to_community_payload_converts_the_first_seen_offset_to_utc():
    payload = to_community_payload(_item(first_seen="2026-11-18T03:00:00+02:00"))

    assert payload["firstseen"] == "2026-11-18 01:00:00"


def test_to_community_payload_rejects_an_item_without_a_sha256():
    item = _item()
    del item["sha256_hash"]

    with pytest.raises(ValueError, match="sha256_hash"):
        to_community_payload(item)


def _encrypted_zip(content: bytes, password: bytes = b"infected") -> bytes:
    """Build a zip like the sample downloads: AES-encrypted, one `.bin` member."""
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(
        buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as archive:
        archive.setpassword(password)
        archive.writestr("sample.bin", content)
    return buffer.getvalue()


def test_extract_sample_returns_the_decrypted_file():
    content = b"MZ synthetic payload"
    sha256 = hashlib.sha256(content).hexdigest()

    assert extract_sample(_encrypted_zip(content), sha256) == content


def test_extract_sample_rejects_a_file_with_another_sha256():
    content = b"MZ synthetic payload"

    with pytest.raises(ValueError, match="sha256"):
        extract_sample(_encrypted_zip(content), "0" * 64)


def test_extract_sample_rejects_content_that_is_not_a_zip():
    with pytest.raises(ValueError, match="zip"):
        extract_sample(b"<html>not a zip</html>", "0" * 64)


def test_extract_sample_rejects_an_archive_with_several_members():
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(
        buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as archive:
        archive.setpassword(b"infected")
        archive.writestr("a.bin", b"a")
        archive.writestr("b.bin", b"b")

    with pytest.raises(ValueError, match="one file"):
        extract_sample(buffer.getvalue(), "0" * 64)
