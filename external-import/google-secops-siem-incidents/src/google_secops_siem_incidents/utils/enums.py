from enum import StrEnum


class Severity(StrEnum):
    """Alert severity levels ordered by priority (higher value = higher severity)."""

    rank: int

    CRITICAL = "CRITICAL", 5
    HIGH = "HIGH", 4
    MEDIUM = "MEDIUM", 3
    LOW = "LOW", 2
    INFO = "INFO", 1

    def __new__(cls, value: str, rank: int) -> "Severity":
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj.rank = rank
        return obj

    @staticmethod
    def _rank(severity: "Severity") -> int:
        return severity.rank

    @staticmethod
    def _coerce(value: object) -> "Severity | None":
        if isinstance(value, Severity):
            return value
        if isinstance(value, str):
            try:
                return Severity(value.upper())
            except ValueError:
                return None
        return None

    def __ge__(self, value: object) -> bool:
        """Return True when this severity is greater than or equal to ``value``."""
        other = self._coerce(value)
        if other is None:
            return NotImplemented
        return self._rank(self) >= self._rank(other)

    def __gt__(self, value: object) -> bool:
        other = self._coerce(value)
        if other is None:
            return NotImplemented
        return self._rank(self) > self._rank(other)

    def __le__(self, value: object) -> bool:
        other = self._coerce(value)
        if other is None:
            return NotImplemented
        return self._rank(self) <= self._rank(other)

    def __lt__(self, value: object) -> bool:
        other = self._coerce(value)
        if other is None:
            return NotImplemented
        return self._rank(self) < self._rank(other)
