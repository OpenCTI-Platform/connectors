"""Extract the observable values to look up in MISP from a STIX 2.1 indicator pattern."""

import re

# Object paths supported in a pattern comparison `<object path> = '<value>'`
_PATTERN_RULES: list[re.Pattern] = [
    re.compile(r"ipv4-addr:value\s*=\s*'((?:\\.|[^'\\])+)'", re.IGNORECASE),
    re.compile(r"ipv6-addr:value\s*=\s*'((?:\\.|[^'\\])+)'", re.IGNORECASE),
    re.compile(r"domain-name:value\s*=\s*'((?:\\.|[^'\\])+)'", re.IGNORECASE),
    re.compile(r"url:value\s*=\s*'((?:\\.|[^'\\])+)'", re.IGNORECASE),
    re.compile(r"email-addr:value\s*=\s*'((?:\\.|[^'\\])+)'", re.IGNORECASE),
    # file:hashes.MD5, file:hashes.'SHA-1', file:hashes.'SHA-256', file:hashes.'SHA-512'
    re.compile(
        r"file:hashes\.(?:'[\w-]+'|\"[\w-]+\"|[\w-]+)\s*=\s*'((?:\\.|[^'\\])+)'",
        re.IGNORECASE,
    ),
]


def _unescape(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def extract_values_from_pattern(pattern: str) -> list[str]:
    """
    Return the distinct values of the supported comparisons of a STIX pattern, in order.

    Example: `[ipv4-addr:value = '1.2.3.4'] OR [file:hashes.MD5 = 'abc']`
    returns `["1.2.3.4", "abc"]`.
    """
    values: list[str] = []
    for regex in _PATTERN_RULES:
        for match in regex.finditer(pattern):
            value = _unescape(match.group(1)).strip()
            if value and value not in values:
                values.append(value)
    return values
