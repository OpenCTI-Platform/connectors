import logging
import os
import tempfile
import zipfile

from attachment_handler.base import BaseAttachmentHandler, ExtractedFile
from connector.utils import compute_file_hashes

logger = logging.getLogger(__name__)

MAX_EXTRACT_DEPTH = 3
MAX_EXTRACTED_SIZE = 100 * 1024 * 1024  # 100 MB


class ArchiveHandler(BaseAttachmentHandler):
    """Handler for archive files: zip, 7z, rar."""

    def supported_extensions(self) -> list[str]:
        return [".zip", ".7z", ".rar"]

    def extract(
        self,
        file_path: str,
        passwords: list[str] | None = None,
    ) -> list[ExtractedFile]:
        lower = file_path.lower()
        if lower.endswith(".zip"):
            return self._extract_zip(file_path, passwords)
        if lower.endswith(".7z"):
            return self._extract_7z(file_path, passwords)
        if lower.endswith(".rar"):
            return self._extract_rar(file_path, passwords)
        return []

    def _extract_zip(
        self,
        file_path: str,
        passwords: list[str] | None,
        depth: int = 0,
    ) -> list[ExtractedFile]:
        if depth >= MAX_EXTRACT_DEPTH:
            return []

        results = []
        total_size = 0

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                # Try without password first, then each password
                pwd_list = [None] + [p.encode() for p in (passwords or [])]
                used_pwd = None

                for pwd in pwd_list:
                    try:
                        # Do NOT call zf.testzip() here: for an encrypted ZIP it
                        # raises before the password is applied, so no password
                        # attempt would ever succeed. Reading the first entry
                        # with the candidate password is the real validation.
                        if pwd:
                            zf.setpassword(pwd)
                        if zf.namelist():
                            zf.read(zf.namelist()[0], pwd=pwd)
                        used_pwd = pwd
                        break
                    except (RuntimeError, zipfile.BadZipFile):
                        continue

                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    if total_size + info.file_size > MAX_EXTRACTED_SIZE:
                        break

                    try:
                        content = zf.read(info.filename, pwd=used_pwd)
                    except RuntimeError:
                        # Try each password individually for this file
                        content = None
                        for pwd in [p.encode() for p in (passwords or [])]:
                            try:
                                content = zf.read(info.filename, pwd=pwd)
                                break
                            except RuntimeError:
                                continue
                        if content is None:
                            continue

                    total_size += len(content)
                    hashes = compute_file_hashes(content)

                    extracted = ExtractedFile(
                        filename=os.path.basename(info.filename),
                        content=content,
                        content_type="application/octet-stream",
                        hashes=hashes,
                        was_encrypted=used_pwd is not None,
                    )
                    results.append(extracted)

        except zipfile.BadZipFile as e:
            logger.warning("Bad ZIP file: %s — %s", file_path, e)
            return []
        except Exception as e:
            logger.warning("ZIP extraction failed: %s — %s", file_path, e)
            return []

        return results

    def _extract_7z(
        self,
        file_path: str,
        passwords: list[str] | None,
    ) -> list[ExtractedFile]:
        try:
            import py7zr
        except ImportError:
            logger.warning("py7zr not installed — cannot extract 7z archives")
            return []

        results = []
        total_size = 0
        pwd_list = [None] + (passwords or [])

        for pwd in pwd_list:
            try:
                with py7zr.SevenZipFile(file_path, mode="r", password=pwd) as archive:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        archive.extractall(path=tmpdir)
                        for root, _, files in os.walk(tmpdir):
                            for fname in files:
                                fpath = os.path.join(root, fname)
                                # Path traversal protection
                                real_path = os.path.realpath(fpath)
                                if not real_path.startswith(
                                    os.path.realpath(tmpdir) + os.sep
                                ):
                                    continue
                                with open(fpath, "rb") as fh:
                                    content = fh.read()
                                total_size += len(content)
                                if total_size > MAX_EXTRACTED_SIZE:
                                    break
                                hashes = compute_file_hashes(content)
                                results.append(
                                    ExtractedFile(
                                        filename=os.path.basename(fname),
                                        content=content,
                                        content_type="application/octet-stream",
                                        hashes=hashes,
                                        was_encrypted=pwd is not None,
                                    )
                                )
                break  # Success
            except Exception as e:
                logger.debug("7z password attempt failed: %s — %s", file_path, e)
                continue

        return results

    def _extract_rar(
        self,
        file_path: str,
        passwords: list[str] | None,
    ) -> list[ExtractedFile]:
        """Extract RAR archive using bsdtar (libarchive-tools).

        Falls back gracefully if bsdtar is not installed.
        """
        import shutil
        import subprocess

        if not shutil.which("bsdtar"):
            logger.warning("bsdtar not installed — cannot extract RAR archives")
            return []

        results = []
        total_size = 0

        with tempfile.TemporaryDirectory() as tmpdir:
            # bsdtar doesn't support RAR passwords, try extraction as-is
            cmd = ["bsdtar", "-x", "-C", tmpdir, "-f", file_path]
            try:
                subprocess.run(cmd, capture_output=True, timeout=60, check=True)
            except subprocess.CalledProcessError as e:
                logger.warning("RAR extraction failed: %s — %s", file_path, e.stderr)
                return []
            except subprocess.TimeoutExpired:
                logger.warning("RAR extraction timed out: %s", file_path)
                return []

            for root, _, files in os.walk(tmpdir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    real_path = os.path.realpath(fpath)
                    if not real_path.startswith(os.path.realpath(tmpdir) + os.sep):
                        continue
                    with open(fpath, "rb") as fh:
                        content = fh.read()
                    total_size += len(content)
                    if total_size > MAX_EXTRACTED_SIZE:
                        break
                    hashes = compute_file_hashes(content)
                    results.append(
                        ExtractedFile(
                            filename=os.path.basename(fname),
                            content=content,
                            content_type="application/octet-stream",
                            hashes=hashes,
                            was_encrypted=False,
                        )
                    )

        return results
