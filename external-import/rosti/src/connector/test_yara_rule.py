"""Check whether a YARA rule compiles, with human-readable error messages.

OpenCTI only accepts a YARA indicator if ``yara.compile(source=rule)`` succeeds
(yara-python, see opencti-graphql/src/python/runtime/check_indicator.py).
``valid_rule`` runs the same check and explains every problem it finds.

The module only needs yara-python (``pip install yara-python==4.5.4``, the
version OpenCTI uses), so it can be copied into other projects as is.

    >>> valid_rule('rule A { strings: $a = "x" condition: $a }')
    (True, [])
    >>> valid_rule('rule A\\n meta:\\n  x = 1\\n condition:\\n  true\\n}')
    (False, ['Rule "A", line 2 (meta:): the rule body does not start with "{". Add "{" after "rule A".'])

Command line:  python test_yara_rule.py rule.yar [more.yar ...]
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass

import yara

__all__ = ["valid_rule"]

# Modules that yara-python ships with; using one without importing it is a common mistake.
YARA_MODULES = {
    "pe",
    "elf",
    "math",
    "hash",
    "dotnet",
    "magic",
    "cuckoo",
    "time",
    "console",
    "string",
    "macho",
    "dex",
    "lnk",
}

# External variables that scanners such as LOKI or THOR define, but plain YARA does not.
COMMON_EXTERNALS = {
    "filename",
    "filepath",
    "extension",
    "filetype",
    "owner",
    "md5",
    "sha1",
    "sha256",
}

_RULE_HEADER = re.compile(
    r"^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z_]\w*)", re.MULTILINE
)
_COMPILER_LINE = re.compile(r"^line (\d+): (.*)$", re.DOTALL)


@dataclass
class _Block:
    """One rule inside the source text."""

    name: str
    start: int  # character offset of "rule"
    end: int  # character offset where the next rule starts
    first_line: int  # 1-based line number of the header


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def valid_rule(rule: str) -> tuple[bool, list[str]]:
    """Check a YARA rule (or several rules in one text) the way OpenCTI does.

    Returns:
        ``(True, [])`` if the rule compiles, otherwise ``(False, errors)``
        where ``errors`` is a list of human-readable messages. The first
        message is always the compiler's own error (YARA stops at the first
        one); further messages are other problems found in the text, so one
        check shows everything that needs fixing.
    """
    if not isinstance(rule, str):
        raise TypeError(f"rule must be a string, not {type(rule).__name__}")

    blocks = _blocks(rule)
    if not blocks:
        return False, [
            'No YARA rule found: the text contains no "rule <name> { ... }" definition.'
        ]

    error = _compile_error(rule)
    if error is None:
        return True, []

    # YARA reports only its first error; look for the other common problems too.
    # The static checks also know the exact line, so their wording wins for the
    # same problem, but the compiler's problem always comes first.
    static: dict[tuple, str] = {}
    for key, message in _static_problems(rule, blocks):
        static.setdefault(key, message)
    key, message = _explain_compiler_error(rule, blocks, error)
    messages = {key: static.get(key, message)}
    for key, message in static.items():
        messages.setdefault(key, message)
    return False, list(messages.values())


# ---------------------------------------------------------------------------
# Compiling
# ---------------------------------------------------------------------------


def _compile_error(source: str) -> str | None:
    # pylint: disable=c-extension-no-member
    try:
        yara.compile(source=source)
    except (yara.SyntaxError, yara.Error) as e:
        return str(e)
    return None


# ---------------------------------------------------------------------------
# Locating rules and lines
# ---------------------------------------------------------------------------


def _blocks(source: str) -> list[_Block]:
    code = _strip_comments(source)
    headers = list(_RULE_HEADER.finditer(code))
    blocks = []
    for i, match in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(code)
        line = code.count("\n", 0, match.start()) + 1
        blocks.append(_Block(match.group(1), match.start(), end, line))
    return blocks


def _rule_at_line(blocks: list[_Block], line: int) -> _Block | None:
    if line <= 0:
        return blocks[-1] if blocks else None
    found = None
    for block in blocks:
        if block.first_line <= line:
            found = block
    return found


def _where(source: str, block: _Block | None, line: int) -> str:
    """'Rule "A", line 2 (meta:)' / 'Rule "A", at the end'."""
    prefix = f'Rule "{block.name}", ' if block else ""
    if line <= 0:
        return f"{prefix}at the end" if block else "At the end"
    lines = source.splitlines()
    text = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    if len(text) > 60:
        text = text[:57] + "..."
    where = f"{prefix}line {line}" if block else f"Line {line}"
    return where + (f" ({text})" if text else "")


def _line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


# ---------------------------------------------------------------------------
# Explaining the compiler's error
# ---------------------------------------------------------------------------


# (compiler message pattern, problem kind, explanation). In the explanation,
# {name} is the rule name and {0}, {1} are the pattern's groups.
_EXPLANATIONS = [
    (
        r"unexpected <(meta|strings|condition)>, expecting '\{'",
        "missing_brace",
        'the rule body does not start with "{{". Add "{{" after "rule {name}".',
    ),
    (
        r'undefined string "(\$\w*)"',
        "undefined_string",
        'the condition uses {0}, but no string {0} is defined in the "strings:" section.',
    ),
    (
        r'unreferenced string "(\$\w*)"',
        "unreferenced_string",
        "string {0} is defined but never used in the condition. "
        "YARA does not allow unused strings: use it in the condition or remove it.",
    ),
    (r'undefined identifier "(\w+)"', "undefined_identifier", None),
    (
        r'duplicated string identifier "(\$\w*)"',
        "duplicate_string",
        "string {0} is defined more than once.",
    ),
    (
        r'duplicated identifier "(\w+)"',
        "duplicate_rule",
        'there is more than one rule named "{0}". Rule names must be unique.',
    ),
    (
        r'invalid regular expression "(\$\w*)": (.*)',
        "invalid_regex",
        "the regular expression {0} is invalid ({1}).",
    ),
    (
        r'unknown module "(\w+)"',
        "unknown_module",
        'imports the module "{0}", which this YARA does not provide.',
    ),
    (
        r"unexpected end of file, expecting '\}'",
        "truncated",
        'the rule ends before its closing "}}". It looks truncated.',
    ),
    (
        r"unexpected end of file, expecting text string",
        "truncated",
        'a text string is not closed (missing "). The rule looks truncated.',
    ),
    (
        r"unexpected end of file",
        "truncated",
        "the rule ends unexpectedly, for example in the middle of the condition. "
        "It looks truncated.",
    ),
    (
        r"expecting <condition>",
        "missing_condition",
        '"condition:" is missing or misspelled. Every rule needs a condition.',
    ),
]


def _explain_compiler_error(
    source: str, blocks: list[_Block], error: str
) -> tuple[tuple, str]:
    match = _COMPILER_LINE.match(error.strip())
    line, raw = (int(match.group(1)), match.group(2)) if match else (0, error.strip())
    block = _rule_at_line(blocks, line)
    where = _where(source, block, line)
    name = block.name if block else ""

    for pattern, kind, template in _EXPLANATIONS:
        found = re.search(pattern, raw)
        if not found:
            continue
        groups = found.groups()
        if kind == "undefined_identifier":
            text = _identifier_hint(groups[0])
        else:
            text = template.format(*groups, name=name)
        # rules and modules are global; strings belong to a rule
        subject = groups[0] if kind in ("duplicate_rule", "unknown_module") else name
        extra = (
            groups[:1]
            if kind
            in (
                "undefined_string",
                "unreferenced_string",
                "undefined_identifier",
                "duplicate_string",
                "invalid_regex",
            )
            else ()
        )
        return (kind, subject, *extra), f"{where}: {text}"
    return ("other", name, raw), f"{where}: YARA cannot compile this ({raw})."


def _identifier_hint(identifier: str) -> str:
    if identifier in YARA_MODULES:
        return (
            f'the rule uses the "{identifier}" module but does not import it. '
            f'Add the line import "{identifier}" above the rule.'
        )
    if identifier in COMMON_EXTERNALS:
        return (
            f'"{identifier}" is an external variable that scanners such as LOKI or THOR provide. '
            "Plain YARA (and OpenCTI) does not know it, so the rule cannot be used there."
        )
    return (
        f'"{identifier}" is not defined. It is probably another rule that is not included, '
        "an external variable, or a typo."
    )


# ---------------------------------------------------------------------------
# Static checks (find the problems YARA would report after its first error)
# ---------------------------------------------------------------------------


def _strip_comments(source: str) -> str:
    """Blank out comments, keeping offsets and line numbers."""

    def blank(match: re.Match) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    pattern = r'"(?:\\.|[^"\\\n])*"|/\*.*?\*/|//[^\n]*'
    return re.sub(
        pattern,
        lambda m: m.group(0) if m.group(0).startswith('"') else blank(m),
        source,
        flags=re.DOTALL,
    )


def _strip_literals(code: str) -> str:
    """Blank out text strings and regular expressions, keeping offsets."""

    def blank(text: str) -> str:
        return re.sub(r"[^\n]", " ", text)

    code = re.sub(r'"(?:\\.|[^"\\\n])*"', lambda m: blank(m.group(0)), code)
    return re.sub(
        r"(=\s*)(/(?:\\.|[^/\\\n])+/)",
        lambda m: m.group(1) + blank(m.group(2)),
        code,
    )


def _section(body: str, name: str, until: tuple[str, ...]) -> tuple[int, str] | None:
    match = re.search(rf"\b{name}\s*:", body)
    if not match:
        return None
    start = match.end()
    end = len(body)
    for other in until:
        nxt = re.search(rf"\b{other}\s*:", body[start:])
        if nxt:
            end = min(end, start + nxt.start())
    return start, body[start:end]


def _static_problems(source: str, blocks: list[_Block]):
    code = _strip_literals(_strip_comments(source))
    for block in blocks:
        body = code[block.start : block.end]
        header = _RULE_HEADER.match(body)
        after = body[header.end() :] if header else body
        # optional tags ": tag1 tag2", then the body must open with "{"
        tags = re.match(r"\s*(?::(?:\s*\w+)*)?\s*", after)
        rest = after[tags.end() :]
        if rest and not rest.startswith("{"):
            line = _line_of(
                source, block.start + (header.end() if header else 0) + tags.end()
            )
            yield ("missing_brace", block.name), (
                f'{_where(source, block, line)}: the rule body does not start with "{{". '
                f'Add "{{" after "rule {block.name}".'
            )

        strings = _section(body, "strings", ("condition",))
        condition = _section(body, "condition", ())
        if not condition:
            continue
        defined: dict[str, int] = {}
        if strings:
            for match in re.finditer(r"(\$\w*)\s*=", strings[1]):
                defined.setdefault(
                    match.group(1), block.start + strings[0] + match.start()
                )
        cond_offset, cond_text = condition
        uses_them = re.search(r"\bthem\b", cond_text) is not None
        wildcards = [m.group(1) for m in re.finditer(r"\$(\w*)\*", cond_text)]
        referenced: dict[str, int] = {}
        for match in re.finditer(r"[$#@!](\w+)(?!\*)\b", cond_text):
            referenced.setdefault(
                "$" + match.group(1), block.start + cond_offset + match.start()
            )

        for ref, offset in referenced.items():
            if ref not in defined:
                yield ("undefined_string", block.name, ref), (
                    f"{_where(source, block, _line_of(source, offset))}: the condition uses {ref}, "
                    f'but no string {ref} is defined in the "strings:" section.'
                )
        if uses_them:
            continue
        for name, offset in defined.items():
            if name == "$" or name in referenced:
                continue
            if any(name[1:].startswith(prefix) for prefix in wildcards):
                continue
            yield ("unreferenced_string", block.name, name), (
                f"{_where(source, block, _line_of(source, offset))}: string {name} is defined but never "
                "used in the condition. YARA does not allow unused strings: use it in the condition or remove it."
            )


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def main(paths: list[str]) -> int:
    if not paths:
        print("usage: python test_yara_rule.py rule.yar [more.yar ...]")
        return 2
    all_valid = True
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as handle:
            ok, errors = valid_rule(handle.read())
        all_valid &= ok
        print(f"{path}: {'valid' if ok else 'INVALID'}")
        for error in errors:
            print(f"  - {error}")
    return 0 if all_valid else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
