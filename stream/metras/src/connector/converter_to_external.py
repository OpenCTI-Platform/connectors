"""Convert OpenCTI Indicator events into Metras custom-blocklist payloads.

Metras has no create-IOC/create-rule API; the only indicator-writable surface is
the custom blocklist, which accepts FILE PATHS only. So only indicators that carry
a file name or path are convertible — everything else is reported as unconvertible.
"""

import re

from connector.utils import slugify

# Matches file:name = 'value' and file:name='value' (single or double quotes)
_FILE_NAME_RE = re.compile(r"file:name\s*=\s*'([^']+)'|file:name\s*=\s*\"([^\"]+)\"")
# Matches directory:path = 'C:\dir' to combine with a file name if present
_DIR_PATH_RE = re.compile(
    r"directory:path\s*=\s*'([^']+)'|directory:path\s*=\s*\"([^\"]+)\""
)

_NAME_PREFIX = "opencti-"


class ConverterToExternal:
    def __init__(
        self, action: str = "ALERT", platform: str = "windows", severity: str = "Medium"
    ) -> None:
        self.action = action
        self.platform = platform
        self.severity = severity

    @staticmethod
    def extract_file_paths(stix_data: dict) -> list[str]:
        """Extract file names/paths from an indicator's STIX pattern.

        Returns an empty list if the indicator carries no file name/path (e.g. it
        is an IP/domain/hash-only indicator that cannot be pushed to Metras).
        """
        pattern = stix_data.get("pattern") or ""
        if not pattern:
            return []

        def _unescape(value: str) -> str:
            # STIX 2.1 string literals escape backslash and single-quote:
            # 'C:\\Windows' represents C:\Windows.
            return value.replace("\\\\", "\\").replace("\\'", "'")

        names = [_unescape(m[0] or m[1]) for m in _FILE_NAME_RE.findall(pattern)]
        dirs = [_unescape(m[0] or m[1]) for m in _DIR_PATH_RE.findall(pattern)]
        paths: list[str] = []
        if names and dirs:
            for d in dirs:
                sep = "" if d.endswith(("\\", "/")) else "\\"
                for n in names:
                    paths.append(f"{d}{sep}{n}")
        else:
            paths.extend(names)
        # De-duplicate, keep order
        seen, result = set(), []
        for p in paths:
            if p and p not in seen:
                seen.add(p)
                result.append(p)
        return result

    @staticmethod
    def blocklist_name(stix_data: dict) -> str:
        """Deterministic blocklist name derived from the indicator NAME (not its
        volatile STIX ID), so updates/deletes resolve to the same entry."""
        name = stix_data.get("name") or stix_data.get("id", "indicator")
        return f"{_NAME_PREFIX}{slugify(name)}"

    def build_item(self, stix_data: dict) -> dict | None:
        """Build a custom-blocklist create item, or None if not convertible."""
        file_paths = self.extract_file_paths(stix_data)
        if not file_paths:
            return None
        description = (
            stix_data.get("description")
            or f"Imported from OpenCTI indicator {stix_data.get('id', '')}"
        )[:500]
        return {
            "name": self.blocklist_name(stix_data),
            "description": description,
            "platform": self.platform,
            "action": self.action,
            "severity": self.severity,
            "file_paths": file_paths,
        }
