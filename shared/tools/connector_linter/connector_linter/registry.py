"""Check registry for the connector linter."""

import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar

from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    ConnectorType,
    Severity,
)

CheckFunction = Callable[[ConnectorContext], list[CheckFinding]]


@dataclass
class CheckDescriptor:
    """Metadata about a registered check."""

    code: str
    name: str
    description: str
    severity: Severity
    func: CheckFunction
    applicable_types: frozenset[ConnectorType] | None = field(default=None)
    module_doc: str | None = field(default=None)


class CheckRegistry:
    """Global registry of check functions.

    Usage::

        @CheckRegistry.register(code="VC101", name="...", description="...", severity=Severity.ERROR)
        def check_fn(ctx: ConnectorContext) -> list[CheckFinding]:
            ...

        CheckRegistry.get_all()
        CheckRegistry.get_by_prefix("VC1xx")
    """

    _checks: ClassVar[dict[str, CheckDescriptor]] = {}

    @classmethod
    def register(
        cls,
        code: str,
        name: str,
        description: str,
        severity: Severity = Severity.ERROR,
        applicable_types: set[ConnectorType] | frozenset[ConnectorType] | None = None,
    ) -> Callable[[CheckFunction], CheckFunction]:
        def decorator(func: CheckFunction) -> CheckFunction:
            module = inspect.getmodule(func)
            cls._checks[code] = CheckDescriptor(
                code=code,
                name=name,
                description=description,
                severity=severity,
                func=func,
                applicable_types=(
                    frozenset(applicable_types) if applicable_types else None
                ),
                module_doc=module.__doc__ if module else None,
            )
            return func

        return decorator

    @classmethod
    def get_all(cls) -> dict[str, CheckDescriptor]:
        return dict(cls._checks)

    @classmethod
    def get_by_prefix(cls, prefix: str) -> dict[str, CheckDescriptor]:
        clean = prefix.rstrip("x")
        return {
            code: desc for code, desc in cls._checks.items() if code.startswith(clean)
        }
