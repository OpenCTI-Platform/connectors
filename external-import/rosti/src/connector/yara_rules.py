"""Make Rösti YARA rules acceptable to OpenCTI.

OpenCTI checks every YARA indicator with ``yara.compile(source=pattern)``
(yara-python, see opencti-graphql/src/python/runtime/check_indicator.py) and
rejects the indicator if that fails. Each Rösti rule becomes one indicator,
so a rule that uses another rule of the same report (for example a private
helper rule) does not compile on its own.

``prepare_yara_patterns`` compiles every rule the same way, with ``include``
disabled: an included file would be read from the connector's machine and
does not exist where OpenCTI checks or uses the rule. A rule that only fails
because it uses other rules of the report gets those rules prepended to its
pattern, as private rules so that they cannot match on their own; anything
that still does not compile is skipped with the compiler's error message
instead of failing in OpenCTI.
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
    # Rules of the same report prepended to the pattern, dependencies first.
    dependencies: list[str]


@dataclass
class SkippedYara:
    rule: Yara
    # The compiler's message, e.g. 'line 3: undefined string "$b"'
    error: str


# The compiler's message for a rule (or variable) that is not defined.
_UNDEFINED = re.compile(r'undefined identifier "(\w+)"')
# A rule header, with its modifiers (private, global) if any.
# Helpers declared in other layouts (e.g. after a comment on the same line)
# are not rewritten; ``_resolve`` then finds them still public and skips the rule.
_RULE_HEADER = re.compile(
    r"^(?P<indent>[ \t]*)(?P<modifiers>(?:(?:private|global)\s+)*)rule(?=\s)",
    re.MULTILINE,
)


def compile_error(source: str) -> str | None:
    """Compile ``source`` as OpenCTI does, without includes.

    Returns the compiler's error message, or None if the rule compiles.
    """
    try:
        yara.compile(source=source, includes=False)
    except yara.Error as e:
        return str(e)
    return None


def _as_private(source: str) -> str:
    """``source`` with every rule declared private (other modifiers are kept)."""

    def make_private(match: re.Match[str]) -> str:
        if "private" in match["modifiers"].split():
            return match[0]
        return f"{match['indent']}{match['modifiers']}private rule"

    return _RULE_HEADER.sub(make_private, source)


def _helpers(dependencies: list[str], by_name: dict[str, Yara]) -> list[str]:
    return [_as_private(by_name[name].rule.strip()) for name in dependencies]


def _public_helpers(helpers: list[str]) -> list[str]:
    """Rules in ``helpers`` that are still public, as YARA itself parses them."""
    compiled = yara.compile(source="\n\n".join(helpers), includes=False)
    return sorted(r.identifier for r in compiled if not r.is_private)


def _resolve(rule: Yara, by_name: dict[str, Yara]) -> YaraPattern | SkippedYara:
    """Compile ``rule``, adding the rules of the report the compiler reports missing.

    Only names the compiler reports as undefined are added, so names that
    appear in comments, metadata or strings never pull in other rules. Each
    round adds a missing rule or moves one in front of the rule that uses it;
    the search ends when an order of rules repeats, so it always terminates.
    """
    dependencies: list[str] = []
    tried: set[tuple[str, ...]] = set()
    while tuple(dependencies) not in tried:
        tried.add(tuple(dependencies))
        helpers = _helpers(dependencies, by_name)
        pattern = "\n\n".join([*helpers, rule.rule.strip()])
        error = compile_error(pattern)
        if error is None:
            public = _public_helpers(helpers) if helpers else []
            if public:
                # A public helper could match on its own and report a hit for
                # this rule, so the combined pattern is not used.
                error = f"helper rule {', '.join(public)} could not be made private"
                break
            return YaraPattern(rule, pattern, dependencies)
        match = _UNDEFINED.search(error)
        name = match[1] if match else None
        if name is None or name == rule.name or name not in by_name:
            break
        # A rule must be defined before it is used: put the missing one first.
        if name in dependencies:
            dependencies.remove(name)
        dependencies.insert(0, name)
    if dependencies:
        error = f"{error} (with helper rules {', '.join(dependencies)} prepended)"
    return SkippedYara(rule, error)


def prepare_yara_patterns(
    rules: list[Yara],
) -> tuple[list[YaraPattern], list[SkippedYara]]:
    """Return the rules OpenCTI will accept, and the ones it would reject."""
    by_name = {rule.name: rule for rule in rules}
    accepted: list[YaraPattern] = []
    skipped: list[SkippedYara] = []
    for rule in rules:
        result = _resolve(rule, by_name)
        if isinstance(result, YaraPattern):
            accepted.append(result)
        else:
            skipped.append(result)
    return accepted, skipped
