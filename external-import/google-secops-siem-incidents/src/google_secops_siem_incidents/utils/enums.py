"""Enums used in the Google SecOps SIEM Incidents connector."""

from enum import StrEnum


class Severity(StrEnum):
    """Alert severity levels ordered by priority (higher value = higher severity)."""

    rank: int

    # NAME = value, rank
    CRITICAL = "CRITICAL", 5
    HIGH = "HIGH", 4
    MEDIUM = "MEDIUM", 3
    LOW = "LOW", 2
    INFO = "INFO", 1

    def __new__(cls, value: str, rank: int = 0) -> "Severity":
        """Create a new Severity enum member with a rank attribute."""
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
                return Severity(value.upper())  # pylint: disable=no-value-for-parameter
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
        """Return True when this severity is greater than ``value``."""
        other = self._coerce(value)
        if other is None:
            return NotImplemented
        return self._rank(self) > self._rank(other)

    def __le__(self, value: object) -> bool:
        """Return True when this severity is less than or equal to ``value``."""
        other = self._coerce(value)
        if other is None:
            return NotImplemented
        return self._rank(self) <= self._rank(other)

    def __lt__(self, value: object) -> bool:
        """Return True when this severity is less than ``value``."""
        other = self._coerce(value)
        if other is None:
            return NotImplemented
        return self._rank(self) < self._rank(other)


class Priority(StrEnum):
    """Alert priority levels ordered by importance (higher value = higher priority)."""

    rank: int

    # NAME = value, rank
    CRITICAL = "CRITICAL", 5
    HIGH = "HIGH", 4
    MEDIUM = "MEDIUM", 3
    LOW = "LOW", 2
    INFO = "INFO", 1

    def __new__(cls, value: str, rank: int = 0) -> "Priority":
        """Create a new Priority enum member with a rank attribute."""
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj.rank = rank
        return obj

    @staticmethod
    def _rank(priority: "Priority") -> int:
        return priority.rank

    @staticmethod
    def _coerce(value: object) -> "Priority | None":
        if isinstance(value, Priority):
            return value
        if isinstance(value, str):
            try:
                return Priority(value.upper())  # pylint: disable=no-value-for-parameter
            except ValueError:
                return None
        return None

    def __ge__(self, value: object) -> bool:
        """Return True when this priority is greater than or equal to ``value``."""
        other = self._coerce(value)
        if other is None:
            return NotImplemented
        return self._rank(self) >= self._rank(other)

    def __gt__(self, value: object) -> bool:
        """Return True when this priority is greater than ``value``."""
        other = self._coerce(value)
        if other is None:
            return NotImplemented
        return self._rank(self) > self._rank(other)

    def __le__(self, value: object) -> bool:
        """Return True when this priority is less than or equal to ``value``."""
        other = self._coerce(value)
        if other is None:
            return NotImplemented
        return self._rank(self) <= self._rank(other)

    def __lt__(self, value: object) -> bool:
        """Return True when this priority is less than ``value``."""
        other = self._coerce(value)
        if other is None:
            return NotImplemented
        return self._rank(self) < self._rank(other)
