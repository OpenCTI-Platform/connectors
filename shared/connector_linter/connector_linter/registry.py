"""Check registry for the connector linter.

Provides a decorator-based registration system for checks.
Each check is a callable that receives a ConnectorContext and returns CheckFinding(s).
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar

from connector_linter.models import CheckFinding, ConnectorContext, Severity

# Type alias for check functions
CheckFunction = Callable[[ConnectorContext], list[CheckFinding]]


@dataclass
class CheckDescriptor:
    """Metadata about a registered check."""

    code: str
    name: str
    description: str
    severity: Severity
    func: CheckFunction


class CheckRegistry:
    """Global registry of all available checks."""

    _checks: ClassVar[dict[str, CheckDescriptor]] = {}

    @classmethod
    def register(
        cls,
        code: str,
        name: str,
        description: str,
        severity: Severity = Severity.ERROR,
    ) -> Callable[[CheckFunction], CheckFunction]:
        """Decorator to register a check function.

        Usage:
            @CheckRegistry.register(
                code="VC101",
                name="has-metadata-dir",
                description="Connector must have a __metadata__ directory",
            )
            def check_metadata_dir(ctx: ConnectorContext) -> list[CheckFinding]:
                ...
        """

        def decorator(func: CheckFunction) -> CheckFunction:
            cls._checks[code] = CheckDescriptor(
                code=code,
                name=name,
                description=description,
                severity=severity,
                func=func,
            )
            return func

        return decorator

    @classmethod
    def get_all(cls) -> dict[str, CheckDescriptor]:
        """Get all registered checks."""
        return dict(cls._checks)

    @classmethod
    def get_by_prefix(cls, prefix: str) -> dict[str, CheckDescriptor]:
        """Get checks matching a prefix like 'VC1' or 'VC1xx'."""
        clean_prefix = prefix.rstrip("x")
        return {
            code: desc
            for code, desc in cls._checks.items()
            if code.startswith(clean_prefix)
        }
