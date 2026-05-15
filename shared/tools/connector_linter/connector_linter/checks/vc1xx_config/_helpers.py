"""Helpers for configuration-file parsing.

Extracts environment variables from ``docker-compose.yml`` and
``.env.sample`` files, including commented-out lines.  Also locates
``config.yml.sample`` and scans for ``ChangeMe`` placeholder values.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from connector_linter.models import ConnectorContext


@dataclass
class EnvVar:
    """A parsed environment variable."""

    name: str
    value: str
    line: int
    file_path: Path
    is_commented: bool


# ---------------------------------------------------------------------------
# Regex: docker-compose.yml environment lines
#
# Matches lines like:
#     - OPENCTI_URL=http://localhost       (uncommented)
#   #   - OPENCTI_URL=http://localhost     (commented out)
#
# Capture groups:
#   commented — leading "#" (present when the line is commented out)
#   name      — uppercase env var name (e.g. OPENCTI_TOKEN)
#   value     — everything after "=" up to an optional inline comment
#
# Trailing inline comments (# …) are stripped from the value.
# ---------------------------------------------------------------------------
_COMPOSE_ENV_RE = re.compile(
    r"^(?P<commented>\s*#)?\s*-\s*(?P<name>[A-Z][A-Z0-9_]*)=(?P<value>[^#\n]*?)(?:\s*#.*)?\s*$",
)

# ---------------------------------------------------------------------------
# Regex: .env.sample (dotenv-style) lines
#
# Matches lines like:
#   OPENCTI_TOKEN=ChangeMe               (uncommented)
#   # OPENCTI_TOKEN=ChangeMe             (commented out)
#
# Same capture groups as _COMPOSE_ENV_RE (commented, name, value).
# The difference is the absence of the YAML list marker "- ".
# ---------------------------------------------------------------------------
_DOTENV_RE = re.compile(
    r"^(?P<commented>\s*#)?\s*(?P<name>[A-Z][A-Z0-9_]*)=(?P<value>[^#\n]*?)(?:\s*#.*)?\s*$",
)


def _parse_lines(
    file_path: Path,
    lines: list[str],
    pattern: re.Pattern[str],
) -> list[EnvVar]:
    """Extract EnvVar entries from raw lines.

    Iterates line-by-line, applying the given regex ``pattern`` to each line.
    Both commented and uncommented matches are captured — the ``is_commented``
    flag lets callers decide which to keep or skip.
    """
    results: list[EnvVar] = []
    for line_no, line in enumerate(lines, 1):
        m = pattern.match(line)
        if m:
            results.append(
                EnvVar(
                    name=m.group("name"),
                    value=m.group("value").strip(),
                    line=line_no,
                    file_path=file_path,
                    is_commented=bool(m.group("commented")),
                ),
            )
    return results


def extract_env_vars_from_docker_compose(ctx: ConnectorContext) -> list[EnvVar]:
    """Extract environment variables from docker-compose.yml."""
    compose_path = ctx.path / "docker-compose.yml"
    if not compose_path.is_file():
        return []
    with compose_path.open(encoding="utf-8") as f:
        return _parse_lines(compose_path, f.readlines(), _COMPOSE_ENV_RE)


def extract_env_vars_from_env_sample(ctx: ConnectorContext) -> list[EnvVar]:
    """Extract environment variables from .env.sample."""
    env_path = ctx.path / ".env.sample"
    if not env_path.is_file():
        return []
    with env_path.open(encoding="utf-8") as f:
        return _parse_lines(env_path, f.readlines(), _DOTENV_RE)


def extract_all_env_vars(ctx: ConnectorContext) -> list[EnvVar]:
    """Extract env vars from docker-compose.yml and .env.sample."""
    return extract_env_vars_from_docker_compose(ctx) + extract_env_vars_from_env_sample(
        ctx,
    )


def derive_connector_prefixes(ctx: ConnectorContext) -> str:
    """Derive valid connector-specific prefixes from the directory name.

    Examples:
      ``mandiant``         → ``"MANDIANT"``
      ``abuse-ssl``        → ``"ABUSE_SSL"``
      ``recorded-future``  → ``"RECORDED_FUTURE"``

    """
    dirname = ctx.path.name
    # Hyphen → underscore:  "abuse-ssl" → "ABUSE_SSL"
    return dirname.upper().replace("-", "_")


def has_docker_compose_env(ctx: ConnectorContext) -> bool:
    """Return True if docker-compose.yml exists with environment variables."""
    return bool(extract_env_vars_from_docker_compose(ctx))


def has_env_sample(ctx: ConnectorContext) -> bool:
    """Return True if .env.sample exists."""
    return (ctx.path / ".env.sample").is_file()


@dataclass
class ChangeMeHit:
    """A ChangeMe value found in a config file with wrong case."""

    file_path: Path
    line: int
    raw_value: str


# ---------------------------------------------------------------------------
# Regex: case-insensitive "ChangeMe" placeholder detector
#
# Matches the word "ChangeMe" regardless of case (CHANGEME, changeme, etc.)
# appearing as a YAML value (after ":") or env value (after "="):
#   OPENCTI_TOKEN=changeme         → matches "changeme"
#   token: 'CHANGEME'              → matches "CHANGEME"
#
# Optional surrounding quotes (' or ") and trailing inline comments are
# tolerated but not captured.
# ---------------------------------------------------------------------------
_CHANGEME_LINE_RE = re.compile(
    r"(?:^|[=:]\s*['\"]?)(?P<value>change\s*me)['\"]?\s*(?:#.*)?$",
    re.MULTILINE | re.IGNORECASE,
)


def find_bad_changeme_values(file_path: Path) -> list[ChangeMeHit]:
    """Find ChangeMe values with wrong case in any config file.

    A "bad" value is any case variant of ChangeMe that is *not* the
    canonical form ``ChangeMe`` (e.g. ``CHANGEME``, ``changeme``).

    Commented lines (starting with ``#``) are skipped because they are
    inactive — fixing their case would be noise, and some commented lines
    may intentionally use a different casing as documentation.
    """
    if not file_path.is_file():
        return []
    with file_path.open(encoding="utf-8") as f:
        lines = f.readlines()

    hits: list[ChangeMeHit] = []
    for line_no, line in enumerate(lines, 1):
        # Skip fully commented lines — only active values matter for casing
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        m = _CHANGEME_LINE_RE.search(line)
        if m:
            raw = m.group("value").strip()
            # Only flag if casing does not match the canonical "ChangeMe"
            if raw != "ChangeMe":
                hits.append(ChangeMeHit(file_path, line_no, raw))
    return hits
