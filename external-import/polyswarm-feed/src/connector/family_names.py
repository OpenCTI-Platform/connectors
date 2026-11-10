"""Tell real malware family names from antivirus engine labels.

Live hunting hits carry a ``malware_family`` string. Many hits carry an engine
style label instead of a family name (measured examples: ``Trojan.Packed2``,
``PUA.Generic``, ``Trojan.JS.Agent``, ``Phishing.HTML.Doc``, ``HkcAURkA``),
while others carry real family names (``Copak``, ``Sdum``, ``Satan``,
``Synaptics``, ``Impacket``, ``AsyncRat``). Creating a Malware object for an
engine label would put noise in the OpenCTI knowledge base, so the connector
only creates one when the name passes this check.

The check is deliberately conservative: when a name looks like a label it is
rejected. A rejected name is not lost, the hunting source still keeps it in the
note and in a label.

PolySwarm also serves a list of family names read-only
(``GET /v3/tags/family/list``). It was measured on 2026-11-10 and was not used:
it holds about 880 curated names and does not contain most of the real family
names seen in live hunting hits (Copak, Sdum, Satan, Synaptics, Impacket),
while it does contain generic labels such as ``Agent``. As a source of truth it
would reject real families, so only the rules below decide.
"""

from __future__ import annotations

import re

MIN_NAME_LENGTH = 4
MAX_NAME_LENGTH = 64

# A word in a name that marks it as a label wherever it appears.
_STRONG_GENERIC = frozenset(
    {
        "generic",
        "heur",
        "heuristic",
        "suspicious",
        "malware",
        "unknown",
        "variant",
        "gen",
        "packed",
        "packer",
        "pua",
        "pup",
        "adware",
        "riskware",
        "phishing",
        "malicious",
        "unwanted",
        "undefined",
        "detected",
        "obfuscated",
        "behaveslike",
    }
)

# Words that are a type, platform or format prefix. A name made only of these
# (with or without a strong generic word) is a label.
_TYPE_WORDS = frozenset(
    {
        "trojan",
        "agent",
        "worm",
        "virus",
        "backdoor",
        "downloader",
        "dropper",
        "spyware",
        "ransom",
        "ransomware",
        "exploit",
        "hacktool",
        "tool",
        "application",
        "program",
        "file",
        "script",
        "macro",
        "document",
        "doc",
        "html",
        "js",
        "pdf",
        "win",
        "win32",
        "win64",
        "msil",
        "linux",
        "android",
        "osx",
        "macos",
        "mac",
        "ms",
        "trj",
        "stealer",
        "rat",
        "bot",
        "miner",
        "banker",
        "loader",
        "rootkit",
        "risk",
        "threat",
        "sample",
        "test",
        "other",
        "none",
        "null",
        "na",
        "kd",
        "ai",
    }
)

_ALLOWED_CHARS = re.compile(r"^[A-Za-z0-9_ \-]+$")
# CamelCase split: acronym runs, capitalized words, lowercase words, digits.
_TOKENS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_VOWELS = set("aeiouy")
_MAX_CONSONANT_RUN = 6
_MIN_VOWEL_RATIO = 0.15
_MAX_VOWEL_RATIO = 0.75


def _words(name: str) -> list[str]:
    """Lowercase words of a name: split on separators and CamelCase."""
    words: list[str] = []
    for part in re.split(r"[ _\-]+", name):
        words.extend(token.lower() for token in _TOKENS.findall(part))
    return words


def _looks_random(name: str) -> bool:
    """Whether the letters look like a random string rather than a word."""
    for part in re.split(r"[ _\-]+", name):
        tokens = _TOKENS.findall(part)
        # Several one or two letter pieces in a CamelCase name (HkcAURkA)
        # mean the case changes are random, not word boundaries.
        short = [t for t in tokens if t.isalpha() and len(t) <= 2]
        if len(tokens) >= 3 and len(short) >= 2:
            return True
    letters = [ch.lower() for ch in name if ch.isalpha()]
    if len(letters) >= 5:
        ratio = sum(ch in _VOWELS for ch in letters) / len(letters)
        if ratio < _MIN_VOWEL_RATIO or ratio > _MAX_VOWEL_RATIO:
            return True
    if re.search(rf"[^aeiouy\W\d_]{{{_MAX_CONSONANT_RUN},}}", name, re.IGNORECASE):
        return True
    digits = sum(ch.isdigit() for ch in name)
    if digits and digits / len(name) > 0.34:
        return True
    return False


def is_malware_family_name(name: object) -> bool:
    """Return True when ``name`` looks like a real malware family name.

    Rejected: names with dots, slashes, colons, brackets or other punctuation,
    names that are very short or very long, names built from generic words or
    from type prefixes only, and random looking strings.
    """
    if not isinstance(name, str):
        return False
    name = name.strip()
    if not MIN_NAME_LENGTH <= len(name) <= MAX_NAME_LENGTH:
        return False
    if not _ALLOWED_CHARS.match(name):
        return False
    if not any(ch.isalpha() for ch in name):
        return False
    words = _words(name)
    if not words:
        return False
    if any(word in _STRONG_GENERIC for word in words):
        return False
    if all(word in _TYPE_WORDS or word.isdigit() for word in words):
        return False
    return not _looks_random(name)
