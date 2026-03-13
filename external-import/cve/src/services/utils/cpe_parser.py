import re


def parse_cpe_uri(cpe_str: str) -> dict[str, str]:
    """Parse a CPE URI (format 1 or 2.3) and extract vendor, product, and version.

    Args:
        cpe_str: The CPE URI string (e.g. "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")

    Returns:
        A dict with keys: part, vendor, product, version.

    Raises:
        ValueError: If the CPE URI is missing mandatory information.
        NotImplementedError: If the CPE URI format is unknown.
    """
    supported_patterns = {
        "cpe:/": (
            r"^cpe:/(?P<part>[a-z]):"
            r"(?P<vendor>[a-zA-Z0-9_\-]+):"
            r"(?P<product>[a-zA-Z0-9_\-]+):"
            r"(?P<version>[a-zA-Z0-9_\-]+)"
        ),
        "cpe:2.3": (
            r"^cpe:2\.3:(?P<part>[a-z]+):"
            r"(?P<vendor>[^:]+):"
            r"(?P<product>[^:]+):"
            r"(?P<version>[^:]+)"
        ),
    }
    for key, supported_pattern in supported_patterns.items():
        if cpe_str.startswith(key):
            match = re.match(pattern=supported_pattern, string=cpe_str)
            if match is not None:
                return {
                    "part": match.group("part"),
                    "vendor": match.group("vendor"),
                    "product": match.group("product"),
                    "version": match.group("version"),
                }
            raise ValueError(f"CPE URI is missing mandatory information: {cpe_str}")
    raise NotImplementedError(f"Unknown CPE URI format: {cpe_str}")
