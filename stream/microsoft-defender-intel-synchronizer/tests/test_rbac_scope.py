import os
import sys

import pytest

# Ensure the 'src' directory is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import microsoft_defender_intel_synchronizer_connector.rbac_scope


def test_resolve_happy_path():
    name_to_id = {"A": 1, "B": 2, "C": 3}
    configured = ["A", "B"]
    names, ids = (
        microsoft_defender_intel_synchronizer_connector.rbac_scope.resolve_rbac_scope_or_abort(
            configured, name_to_id
        )
    )
    assert names == ["A", "B"]
    assert ids == [1, 2]


def test_resolve_with_duplicates_by_id():
    name_to_id = {"A": 1, "AliasA": 1, "B": 2}
    configured = ["A", "AliasA", "B"]
    names, ids = (
        microsoft_defender_intel_synchronizer_connector.rbac_scope.resolve_rbac_scope_or_abort(
            configured, name_to_id
        )
    )
    assert names == ["A", "B"]
    assert ids == [1, 2]


def test_resolve_missing_raises():
    name_to_id = {"A": 1, "B": 2}
    configured = ["A", "Z"]
    with pytest.raises(
        microsoft_defender_intel_synchronizer_connector.rbac_scope.RbacConfigError
    ):
        microsoft_defender_intel_synchronizer_connector.rbac_scope.resolve_rbac_scope_or_abort(
            configured, name_to_id
        )
