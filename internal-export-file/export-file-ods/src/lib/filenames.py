"""Filename sanitisation helpers for the ``export-file-ods`` connector.

This module is intentionally dependency-free (no ``unogenerator`` / no
``pycti``) so the filename sanitisation contract that guards against path
traversal and extension mangling can be unit-tested without LibreOffice
being available on the CI runner.
"""

import os
from typing import Optional

_UNKNOWN_SUFFIX = ".unknown"
_ODS_SUFFIX = ".ods"
_FALLBACK_BASENAME = "export"


def sanitize_file_name(raw_file_name: Optional[str]) -> str:
    """Return a safe ``<name>.ods`` filename from the request payload.

    The platform sometimes hands the connector a request payload whose
    ``file_name`` is empty, contains directory components, or ends with the
    placeholder ``.unknown`` extension. This helper normalises all three
    cases:

    * Directory components are stripped via :func:`os.path.basename` to
      defend against path traversal when writing under ``./tmp/``.
    * The literal ``.unknown`` suffix is removed (not via
      :meth:`str.rstrip` which would happily trim any trailing characters
      in the set ``{".", "u", "n", "k", "o", "w"}`` — e.g. mangling
      ``file.unk`` to ``file``).
    * An empty / missing ``file_name`` falls back to ``"export"``.
    * An existing ``.ods`` extension (case-insensitive) is preserved
      as-is so a request with ``file_name="report.ods"`` returns
      ``report.ods`` instead of ``report.ods.ods``.
    """
    base = os.path.basename(raw_file_name or "")
    if base.endswith(_UNKNOWN_SUFFIX):
        base = base[: -len(_UNKNOWN_SUFFIX)]
    if not base:
        base = _FALLBACK_BASENAME
    if not base.lower().endswith(_ODS_SUFFIX):
        base = f"{base}{_ODS_SUFFIX}"
    return base


__all__ = ("sanitize_file_name",)
