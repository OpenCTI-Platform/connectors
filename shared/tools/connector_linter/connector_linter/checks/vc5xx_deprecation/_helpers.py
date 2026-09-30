"""Shared AST helpers for vc5xx deprecation checks."""

import ast

# Known helper variable names across the connector codebase.
_HELPER_NAMES = frozenset({"helper", "_helper"})


def is_helper_node(node: ast.expr) -> bool:
    """Return True if *node* refers to a helper variable.

    Accepts:
    - ``ast.Name(id="helper")`` / ``ast.Name(id="_helper")``  (bare name)
    - ``ast.Attribute(attr="helper")`` / ``ast.Attribute(attr="_helper")``
      (qualified, e.g. ``self.helper``)
    """
    if isinstance(node, ast.Name) and node.id in _HELPER_NAMES:
        return True
    if isinstance(node, ast.Attribute) and node.attr in _HELPER_NAMES:
        return True
    return False
