from __future__ import annotations

import re
from typing import Iterable


_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)


def parse_alternates(raw: str | None) -> list[str]:
    if raw is None:
        return []

    text = raw.strip()
    if not text:
        return []

    urls: list[str] = []
    for token in text.split(";"):
        token = token.strip()
        if not token:
            continue

        match = _URL_RE.search(token)
        if not match:
            continue

        url = match.group(0).rstrip(")],.;")
        if url:
            urls.append(url)

    # preserve order but remove duplicates
    seen: set[str] = set()
    out: list[str] = []
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        out.append(url)

    return out


def iter_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out
