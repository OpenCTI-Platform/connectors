"""Minimal ``.env`` reader, to avoid a dependency on python-dotenv.

Supported syntax:

* ``KEY=VALUE`` lines, split on the first ``=``; key and value are trimmed;
* an optional leading ``export``;
* values in matching single or double quotes, kept verbatim (``#``
  included);
* blank lines and lines starting with ``#``;
* on an unquoted value, a trailing `` #comment`` is removed.

Not supported: variable expansion, escape sequences, multi-line values.
"""

from pathlib import Path

_QUOTES = ("'", '"')


def parse_dotenv(text: str) -> dict[str, str]:
    """Parse the content of a ``.env`` file."""
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not key:
            continue
        values[key] = _parse_value(value.strip())
    return values


def _parse_value(value: str) -> str:
    if len(value) >= 2 and value[0] in _QUOTES and value[-1] == value[0]:
        return value[1:-1]
    comment = value.find(" #")
    if comment != -1:
        value = value[:comment]
    return value.strip()


def read_dotenv(path: Path) -> dict[str, str]:
    """Read a ``.env`` file. A missing file gives an empty dict."""
    try:
        return parse_dotenv(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
