"""
Type aliases for RBAC scoping.
"""

from typing import TypeAlias

# Identity key for dedupe: action/metadata deliberately ignored
ScopeKey: TypeAlias = tuple[str, str, tuple[int, ...]]

# Per-run scoped write: both arrays present when scoping is active
RBACScope: TypeAlias = tuple[list[str], list[int]]


__all__ = ["ScopeKey", "RBACScope"]
