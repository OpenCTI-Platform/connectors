from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

MISSING = "—"


def display(value: Any, *, empty: str = MISSING) -> str:
    if value is None:
        return empty
    if isinstance(value, list):
        if not value:
            return empty
        if len(value) == 1:
            s = str(value[0]).strip()
            return s if s else empty
        return ", ".join(str(v).strip() for v in value if str(v).strip()) or empty
    s = str(value).strip()
    return s if s else empty


@dataclass
class MarkdownNote:
    _lines: list[str] = field(default_factory=list)

    def raw(self, line: str) -> MarkdownNote:
        self._lines.append(line)
        return self

    def gap(self) -> MarkdownNote:
        if self._lines and self._lines[-1] != "":
            self._lines.append("")
        return self

    def h2(self, title: str) -> MarkdownNote:
        self.gap()
        self._lines.append(f"## {title}")
        return self

    def h3(self, title: str) -> MarkdownNote:
        self.gap()
        self._lines.append(f"### {title}")
        return self

    def kv(
        self,
        label: str,
        value: Any,
        *,
        cell: Callable[[Any], str] | None = None,
    ) -> MarkdownNote:
        fmt = cell or display
        self._lines.append(f"- **{label}:** {fmt(value)}")
        return self

    def paragraph(self, text: str) -> MarkdownNote:
        if text:
            self._lines.append(text)
        return self

    def bullet(self, text: str) -> MarkdownNote:
        if text:
            self._lines.append(f"- {text}")
        return self

    def indented(self, text: str, prefix: str = "  ") -> MarkdownNote:
        if text:
            self._lines.append(f"{prefix}{text}")
        return self

    def table(
        self,
        headers: Sequence[str],
        rows: Iterable[Sequence[Any]],
        *,
        cell: Callable[[Any], str] | None = None,
    ) -> MarkdownNote:
        fmt = cell or display
        self._lines.append("| " + " | ".join(headers) + " |")
        self._lines.append("| " + " | ".join("---" for _ in headers) + " |")
        for row in rows:
            self._lines.append("| " + " | ".join(fmt(c) for c in row) + " |")
        return self

    def extend(self, lines: Iterable[str]) -> MarkdownNote:
        self._lines.extend(lines)
        return self

    def build(self) -> str:
        if not self._lines:
            return ""
        return "\n".join(self._lines).rstrip() + "\n"
