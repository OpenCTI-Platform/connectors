from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from user_agents import parse as parse_user_agent

UA_VENDOR_MAP = {
    "Chrome": "Google",
    "Firefox": "Mozilla",
    "Safari": "Apple",
    "Edge": "Microsoft",
    "Opera": "Opera Software",
    "curl": "curl",
    "python-requests": "Python Software Foundation",
    "Wget": "GNU",
    "TeamViewer": "TeamViewer AG",
}


@dataclass
class ParsedUserAgent:
    """Parsed User-Agent string mapped to STIX Software fields."""

    software_name: str
    software_version: str
    os_name: Optional[str]
    os_version: Optional[str]
    device_type: Optional[str]
    raw_string: str
    vendor: Optional[str]


class UserAgentParser:
    """Parses User-Agent strings into structured data."""

    def __init__(self, vendor_map: dict | None = None):
        self._vendor_map = vendor_map or UA_VENDOR_MAP

    def parse(self, ua_string: str) -> Optional[ParsedUserAgent]:
        """Parse a User-Agent string and return structured data."""
        if not isinstance(ua_string, str) or not ua_string.strip():
            return None

        raw = ua_string.strip()
        fallback = self._parse_common_cli_clients(raw)
        if fallback is not None:
            return fallback

        try:
            parsed = parse_user_agent(raw)
        except Exception:
            return None

        software_name = parsed.browser.family or ""
        software_version = parsed.browser.version_string or ""
        os_name = parsed.os.family or None
        os_version = parsed.os.version_string or None

        device_type: Optional[str] = None
        if parsed.is_bot:
            device_type = "Bot"
        elif parsed.is_mobile:
            device_type = "Mobile"
        elif parsed.is_tablet:
            device_type = "Tablet"
        elif parsed.is_pc:
            device_type = "PC"

        if (
            software_name in ("", "Other")
            and not software_version
            and (os_name in (None, "Other"))
            and not parsed.is_bot
        ):
            return None

        vendor = self._vendor_map.get(software_name)
        return ParsedUserAgent(
            software_name=software_name,
            software_version=software_version,
            os_name=None if os_name == "Other" else os_name,
            os_version=os_version,
            device_type=device_type,
            raw_string=raw,
            vendor=vendor,
        )

    def to_stix_software(self, parsed: ParsedUserAgent) -> dict:
        """Convert a parsed user agent to STIX Software-like properties."""
        description_parts = ["Browser"]
        if parsed.os_name:
            os_label = parsed.os_name
            if parsed.os_version:
                os_label = f"{os_label} {parsed.os_version}"
            description_parts.append(os_label)
        if parsed.device_type:
            description_parts.append(parsed.device_type)

        output = {
            "type": "Software",
            "name": parsed.software_name,
            "x_opencti_description": " - ".join(description_parts),
        }
        if parsed.software_version:
            output["version"] = parsed.software_version
        if parsed.vendor:
            output["vendor"] = parsed.vendor
        return output

    def _parse_common_cli_clients(self, raw: str) -> Optional[ParsedUserAgent]:
        """Handle clients that user-agents may classify as 'Other'."""
        patterns = (
            (r"^(curl)/(\S+)", "curl"),
            (r"^(python-requests)/(\S+)", "python-requests"),
            (r"^(Wget)/(\S+)", "Wget"),
            (r"^(TeamViewer)/(\S+)", "TeamViewer"),
        )
        for pattern, software in patterns:
            match = re.search(pattern, raw, flags=re.IGNORECASE)
            if not match:
                continue
            version = match.group(2)
            canonical_name = software
            if canonical_name.lower() == "teamviewer":
                canonical_name = "TeamViewer"
            elif canonical_name.lower() == "wget":
                canonical_name = "Wget"
            elif canonical_name.lower() == "curl":
                canonical_name = "curl"
            elif canonical_name.lower() == "python-requests":
                canonical_name = "python-requests"

            return ParsedUserAgent(
                software_name=canonical_name,
                software_version=version,
                os_name=None,
                os_version=None,
                device_type=None,
                raw_string=raw,
                vendor=self._vendor_map.get(canonical_name),
            )
        return None
