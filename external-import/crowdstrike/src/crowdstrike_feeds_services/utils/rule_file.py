"""Read the rule file out of a CrowdStrike rule set download.

``GET /intel/entities/rules-latest-files/v1`` lets the caller pick ZIP or
gzip, but FalconPy sends no ``Accept`` header, so the API chooses the
format. Detect it from the content instead of assuming ZIP.
"""

import gzip
import tarfile
import zipfile
import zlib
from io import BytesIO
from pathlib import PurePosixPath

_ZIP_MAGIC = b"PK\x03\x04"
_GZIP_MAGIC = b"\x1f\x8b"


class RuleFileFormatError(ValueError):
    """The download is not a rule file the connector can read."""


def extract_rule_file(content: bytes, file_name: str) -> str:
    """Return the text of ``file_name`` from a rule set download.

    The download can be a ZIP archive, a gzip file (holding the rule file
    itself or a tar archive) or the rule file as plain text. In an archive,
    ``file_name`` is used when present, otherwise the only member with the
    same extension.
    """
    try:
        if content.startswith(_ZIP_MAGIC):
            return _decode(_read_zip(content, file_name))
        if content.startswith(_GZIP_MAGIC):
            data = gzip.decompress(content)
            if tarfile.is_tarfile(BytesIO(data)):
                return _decode(_read_tar(data, file_name))
            return _decode(data)
        return _decode(content)
    except (
        zipfile.BadZipFile,
        tarfile.TarError,
        zlib.error,
        OSError,
        EOFError,
    ) as err:
        raise RuleFileFormatError(
            f"Cannot read {file_name} from the download: {err}"
        ) from err


def _read_zip(content: bytes, file_name: str) -> bytes:
    with zipfile.ZipFile(BytesIO(content)) as archive:
        member = _pick_member(archive.namelist(), file_name)
        return archive.read(member)


def _read_tar(content: bytes, file_name: str) -> bytes:
    with tarfile.open(fileobj=BytesIO(content)) as archive:
        names = [member.name for member in archive.getmembers() if member.isfile()]
        extracted = archive.extractfile(_pick_member(names, file_name))
        if extracted is None:
            raise RuleFileFormatError(f"{file_name} is not a regular file")
        return extracted.read()


def _pick_member(names: list[str], file_name: str) -> str:
    for name in names:
        if PurePosixPath(name).name == file_name:
            return name
    suffix = PurePosixPath(file_name).suffix
    candidates = [name for name in names if PurePosixPath(name).suffix == suffix]
    if len(candidates) == 1:
        return candidates[0]
    raise RuleFileFormatError(
        f"{file_name} not found in the archive (members: {sorted(names)})"
    )


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as err:
        raise RuleFileFormatError(
            f"Download is not a ZIP, gzip or UTF-8 text file "
            f"({len(data)} bytes, starts with {data[:16]!r})"
        ) from err
