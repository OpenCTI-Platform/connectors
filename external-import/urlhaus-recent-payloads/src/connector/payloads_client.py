"""Helpers for the Spamhaus commercial URLhaus payloads endpoints.

Authentication, pagination and retries are handled by `connectors_sdk.SpamhausClient`.
This module only maps the JSON of ``GET /urlhaus/v1/payloads`` and opens the sample
archives of ``GET /urlhaus/v1/files/samples/{sha256_hash}``.
"""

import hashlib
import io
from datetime import datetime, timezone
from typing import Any

import pyzipper

PAYLOADS_PATH = "/urlhaus/v1/payloads"
SAMPLES_PATH = "/urlhaus/v1/files/samples"
SAMPLE_ARCHIVE_PASSWORD = b"infected"
COMMUNITY_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def to_utc_iso(value: datetime) -> str:
    """Format a datetime (UTC assumed when naive) as `2026-01-01T00:00:00Z`."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_community_payload(item: dict[str, Any]) -> dict[str, Any]:
    """Convert a Spamhaus payload to the shape of the community `payloads/recent` API.

    Keeping the community shape lets the connector process both sources identically
    and keeps the stored `last_first_seen` checkpoint format unchanged.

    Raises:
        ValueError: If the item has no `sha256_hash` or an invalid `first_seen`.
    """
    sha256 = item.get("sha256_hash")
    if not sha256:
        raise ValueError("Payload has no sha256_hash")

    first_seen = datetime.fromisoformat(item["first_seen"].replace("Z", "+00:00"))
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)

    return {
        "sha256_hash": sha256,
        "firstseen": first_seen.astimezone(timezone.utc).strftime(
            COMMUNITY_DATETIME_FORMAT
        ),
        "file_type": item.get("file_type"),
        "signature": item.get("signature"),
        "urlhaus_download": item.get("urlhaus_download"),
    }


def extract_sample(archive: bytes, expected_sha256: str) -> bytes:
    """Return the file held by a Spamhaus sample archive.

    Samples come as an AES-encrypted zip (password `infected`) holding one `.bin`
    file.

    Raises:
        ValueError: If the content is not such an archive, or its file does not
            match `expected_sha256`.
    """
    try:
        with pyzipper.AESZipFile(io.BytesIO(archive)) as zip_file:
            names = zip_file.namelist()
            if len(names) != 1:
                raise ValueError("Sample archive must contain exactly one file")
            content = zip_file.read(names[0], pwd=SAMPLE_ARCHIVE_PASSWORD)
    except pyzipper.BadZipFile as err:
        raise ValueError("Sample is not a zip archive") from err
    except RuntimeError as err:  # pyzipper signals a wrong password this way
        raise ValueError("Sample archive cannot be decrypted") from err

    if hashlib.sha256(content).hexdigest() != expected_sha256.lower():
        raise ValueError("Sample sha256 does not match the expected hash")
    return content
