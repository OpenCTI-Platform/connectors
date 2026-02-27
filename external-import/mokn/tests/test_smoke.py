def test_connector_imports() -> None:
    """
    Smoke test to ensure connector modules import correctly.
    :return: None
    """
    import sys
    from pathlib import Path

    import pytest

    repo_root = Path(__file__).resolve().parents[1]
    sys.path.append(str(repo_root / "src"))

    pytest.importorskip("pycti")
    from connector import MoknConnector  # noqa: F401
