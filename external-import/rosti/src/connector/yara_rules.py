"""Make Rösti YARA rules acceptable to OpenCTI.

OpenCTI checks every YARA indicator with ``yara.compile(source=pattern)``
(yara-python, see opencti-graphql/src/python/runtime/check_indicator.py) and
rejects the indicator if that fails. Each Rösti rule becomes one indicator,
so a rule that uses another rule of the same report (for example a private
helper rule) does not compile on its own.

``prepare_yara_patterns`` compiles every rule the same way. A rule that only
fails because it references other rules of the report gets those rules
prepended to its pattern; anything that still does not compile is skipped
with the compiler's error message instead of failing in OpenCTI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import yara
from rosti_client.models import Yara


@dataclass
class YaraPattern:
    rule: Yara
    pattern: str
    dependencies: list[str]


@dataclass
class SkippedYara:
    rule: Yara
    # The compiler's message, e.g. 'line 3: undefined string identifier "$b"'
    error: str


def compile_error(source: str) -> str | None:
    """Compile ``source`` as OpenCTI does: the error message, or None if it compiles."""
    try:
        yara.compile(source=source)
    except yara.Error as e:
        return str(e)
    return None


def _references(rule: Yara, names: set[str]) -> set[str]:
    """Names of other rules (from ``names``) that ``rule`` mentions."""
    found = set()
    for name in names - {rule.name}:
        if re.search(rf"(?<![\w$#@!]){re.escape(name)}(?!\w)", rule.rule):
            found.add(name)
    return found


def _with_dependencies(rule: Yara, by_name: dict[str, Yara]) -> list[str]:
    """Other rules ``rule`` needs, dependencies first (cycles are ignored)."""
    ordered: list[str] = []
    visiting: set[str] = set()
    names = set(by_name)

    def visit(current: Yara) -> None:
        for dep in sorted(_references(current, names)):
            if dep in ordered or dep in visiting or dep == rule.name:
                continue
            visiting.add(dep)
            visit(by_name[dep])
            ordered.append(dep)

    visit(rule)
    return ordered


def prepare_yara_patterns(
    rules: list[Yara],
) -> tuple[list[YaraPattern], list[SkippedYara]]:
    """Return the rules OpenCTI will accept, and the ones it would reject."""
    by_name = {rule.name: rule for rule in rules}
    accepted: list[YaraPattern] = []
    skipped: list[SkippedYara] = []
    for rule in rules:
        source = rule.rule.strip()
        error = compile_error(source)
        if error is None:
            accepted.append(YaraPattern(rule, source, []))
            continue
        dependencies = _with_dependencies(rule, by_name)
        if dependencies:
            combined = "\n\n".join(
                [by_name[d].rule.strip() for d in dependencies] + [source]
            )
            if compile_error(combined) is None:
                accepted.append(YaraPattern(rule, combined, dependencies))
                continue
        skipped.append(SkippedYara(rule, error))
    return accepted, skipped
