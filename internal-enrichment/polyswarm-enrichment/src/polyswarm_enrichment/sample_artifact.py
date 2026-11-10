"""Build an Artifact observable holding a sample downloaded from PolySwarm.

Used only when POLYSWARM_DOWNLOAD_SAMPLE is on. The Artifact carries the live
file bytes, so it is created only from bytes whose SHA-256 matches the hash
PolySwarm reported for the sample.
"""

import base64
import hashlib
import json
import os
import re

import stix2

_MIME_RE = re.compile(r"^[A-Za-z0-9][\w.+-]*/[\w.+-]+$")
_SAFE_NAME_RE = re.compile(r"[^\w.\- ]")


def _safe_name(filenames: list | None, fallback: str) -> str:
    """A plain file name: no directories, no control or odd characters."""
    for candidate in filenames or []:
        name = _SAFE_NAME_RE.sub("_", os.path.basename(str(candidate or "")))
        name = name.strip(" .")[:128]
        if name:
            return name
    return fallback


def build_sample_artifact(
    content: bytes,
    data: dict,
    author_id: str,
    marking_refs: list[str] | None = None,
) -> dict | None:
    """Return the STIX Artifact (as a dict) for ``content``.

    Returns None when the bytes do not match the SHA-256 PolySwarm reported.
    """
    sha256 = hashlib.sha256(content).hexdigest()
    expected = (data.get("sha256") or "").lower()
    if not expected or sha256 != expected:
        return None
    hashes = {
        "SHA-256": sha256,
        "SHA-1": hashlib.sha1(content).hexdigest(),  # noqa: S324 - identifier only
        "MD5": hashlib.md5(content).hexdigest(),  # noqa: S324 - identifier only
    }
    mime = data.get("mime_type")
    mime = mime if mime and _MIME_RE.match(str(mime)) else "application/octet-stream"
    name = _safe_name(data.get("filenames"), sha256)
    extra = {
        "x_opencti_additional_names": [name],
        "x_opencti_description": (
            "LIVE MALWARE SAMPLE downloaded from PolySwarm (SHA-256 "
            f"{sha256}). Do not open or run it outside an isolated analysis "
            "environment."
        ),
        "x_opencti_labels": ["polyswarm:live-malware-sample"],
        "x_opencti_created_by_ref": author_id,
    }
    if data.get("x_opencti_score") is not None:
        extra["x_opencti_score"] = data["x_opencti_score"]
    if marking_refs:
        extra["object_marking_refs"] = list(marking_refs)
    artifact = stix2.Artifact(
        mime_type=mime,
        payload_bin=base64.b64encode(content).decode("ascii"),
        hashes=hashes,
        allow_custom=True,
        **extra,
    )
    return json.loads(artifact.serialize())
