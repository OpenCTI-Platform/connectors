"""Read the rule file out of a CrowdStrike rule set download.

``GET /intel/entities/rules-latest-files/v1`` lets the caller pick ZIP or
gzip, but FalconPy sends no ``Accept`` header, so the API chooses the
format. Detect it from the content instead of assuming ZIP.
"""

import gzip
import logging
import lzma
import tarfile
import zipfile
import zlib
from io import BytesIO
from pathlib import PurePosixPath

from crowdstrike_feeds_services.utils import CrowdStrikeAPIError

logger = logging.getLogger(__name__)

# Local file header, and end of central directory (an empty archive).
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
_GZIP_MAGIC = b"\x1f\x8b"


class RuleFileFormatError(CrowdStrikeAPIError):
    """The download is not a rule file the connector can read."""


def describe_download(content: bytes) -> str:
    """Return the size and first bytes of a download, for error messages."""
    return f"{len(content)} bytes, starts with {content[:16]!r}"


def extract_rule_file(
    content: bytes, file_name: str, excluded: tuple[str, ...] = ()
) -> str:
    """Return the text of ``file_name`` from a rule set download.

    The download can be a ZIP archive, a gzip file (holding the rule file
    itself or a tar archive) or the rule file as plain text. In an archive,
    ``file_name`` is used when present, otherwise the only member with the
    same extension whose name contains none of the ``excluded`` words.
    """
    try:
        if content.startswith(_ZIP_MAGICS):
            return _decode(_read_zip(content, file_name, excluded))
        if content.startswith(_GZIP_MAGIC):
            return _decode_gzip(gzip.decompress(content), file_name, excluded)
        return _decode(content)
    except RuleFileFormatError:
        raise
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        tarfile.TarError,
        zlib.error,
        lzma.LZMAError,
        OSError,
        EOFError,
        NotImplementedError,
        RuntimeError,
    ) as err:
        raise RuleFileFormatError(
            f"Cannot read {file_name} from the download "
            f"({describe_download(content)}): {err}"
        ) from err


def _decode_gzip(data: bytes, file_name: str, excluded: tuple[str, ...]) -> str:
    try:
        archive = tarfile.open(fileobj=BytesIO(data), mode="r:")
    except tarfile.ReadError:
        return _decode(data)
    with archive:
        names = [member.name for member in archive.getmembers() if member.isfile()]
        if not names:
            # Zero blocks read as an empty tar archive: treat them as text.
            return _decode(data)
        extracted = archive.extractfile(_pick_member(names, file_name, excluded))
        if extracted is None:
            raise RuleFileFormatError(f"{file_name} is not a regular file")
        return _decode(extracted.read())


def _read_zip(content: bytes, file_name: str, excluded: tuple[str, ...]) -> bytes:
    with zipfile.ZipFile(BytesIO(content)) as archive:
        member = _pick_member(archive.namelist(), file_name, excluded)
        return archive.read(member)


def _pick_member(names: list[str], file_name: str, excluded: tuple[str, ...]) -> str:
    for name in names:
        if PurePosixPath(name).name == file_name:
            return name
    suffix = PurePosixPath(file_name).suffix
    candidates = [
        name
        for name in names
        if PurePosixPath(name).suffix == suffix
        and not any(word in PurePosixPath(name).name for word in excluded)
    ]
    if len(candidates) == 1:
        logger.warning(
            "%s not found in the rule set archive, reading %s instead",
            file_name,
            candidates[0],
        )
        return candidates[0]
    raise RuleFileFormatError(
        f"{file_name} not found in the archive (members: {sorted(names)})"
    )


def _decode(data: bytes) -> str:
    try:
        # utf-8-sig drops a BOM, which would hide the first rule from the parsers.
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as err:
        raise RuleFileFormatError(
            "Download is not a ZIP, gzip or UTF-8 text file "
            f"({describe_download(data)})"
        ) from err
