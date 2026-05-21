def test_settings_loads() -> None:
    """
    Smoke test: settings can be instantiated.
    :return: None
    """
    import os
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[2]
    sys.path.append(str(repo_root / "src"))

    from connector.settings import ConnectorSettings  # noqa: F401

    os.environ.setdefault("OPENCTI_URL", "http://localhost:8080")
    os.environ.setdefault("OPENCTI_TOKEN", "ChangeMe")
    os.environ.setdefault("CONNECTOR_ID", "00000000-0000-0000-0000-000000000000")
    os.environ.setdefault("CONNECTOR_NAME", "MokN")
    os.environ.setdefault("CONNECTOR_SCOPE", "mokn")
    os.environ.setdefault("CONNECTOR_TYPE", "EXTERNAL_IMPORT")
    os.environ.setdefault("CONNECTOR_DURATION_PERIOD", "PT1H")
    os.environ.setdefault("MOKN_CONSOLE_URL", "https://example.com")
    os.environ.setdefault("MOKN_API_KEY", "ChangeMe")

    ConnectorSettings()
