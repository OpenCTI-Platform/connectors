from datetime import datetime, timezone


class _DummyLogger:
    def info(self, *args, **kwargs) -> None:  # noqa: D401
        return None

    def warning(self, *args, **kwargs) -> None:
        return None

    def error(self, *args, **kwargs) -> None:
        return None


class _DummyHelper:
    connector_logger = _DummyLogger()


class _DummySecret:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_secret_value(self) -> str:
        return self._value


class _DummyMokn:
    def __init__(self) -> None:
        self.console_url = "https://example.com"
        self.api_key = _DummySecret("ChangeMe")
        self.first_run_days_back = 1
        self.tlp_level = "clear"


class _DummyConfig:
    def __init__(self) -> None:
        self.mokn = _DummyMokn()


def _get_type(obj) -> str:
    return getattr(obj, "type", obj.get("type"))


def test_high_threat_creates_indicator_and_sighting() -> None:
    """
    Validate HIGH threat conversion path.
    :return: None
    """
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[2]
    sys.path.append(str(repo_root / "src"))

    from connector.converter_to_stix import ConverterToStix
    from mokn.utils import LoginAttemptStatus

    converter = ConverterToStix(_DummyHelper(), _DummyConfig())
    login_attempt = {
        "ip": "1.1.1.1",
        "threat_level": "HIGH",
        "status": LoginAttemptStatus.INVALID.value,
        "date": datetime.now(timezone.utc).isoformat(),
        "username": "alice",
    }

    objects = converter.process_login_attempt(login_attempt)
    types = {_get_type(obj) for obj in objects}

    assert "indicator" in types
    assert "ipv4-addr" in types
    assert "sighting" in types
    assert "relationship" in types
    assert "user-account" in types


def test_valid_credentials_creates_incident() -> None:
    """
    Validate incident creation for valid credentials.
    :return: None
    """
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[2]
    sys.path.append(str(repo_root / "src"))

    from connector.converter_to_stix import ConverterToStix
    from mokn.utils import LoginAttemptStatus

    converter = ConverterToStix(_DummyHelper(), _DummyConfig())
    login_attempt = {
        "ip": "2.2.2.2",
        "threat_level": "HIGH",
        "status": LoginAttemptStatus.VALID.value,
        "date": datetime.now(timezone.utc).isoformat(),
        "username": "bob",
    }

    objects = converter.process_login_attempt(login_attempt)
    types = {_get_type(obj) for obj in objects}

    assert "incident" in types


def test_medium_threat_creates_observable_only() -> None:
    """
    Validate MEDIUM threat creates observables only.
    :return: None
    """
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[2]
    sys.path.append(str(repo_root / "src"))

    from connector.converter_to_stix import ConverterToStix
    from mokn.utils import LoginAttemptStatus

    converter = ConverterToStix(_DummyHelper(), _DummyConfig())
    login_attempt = {
        "ip": "3.3.3.3",
        "threat_level": "MEDIUM",
        "status": LoginAttemptStatus.INVALID.value,
        "date": datetime.now(timezone.utc).isoformat(),
        "username": "charlie",
    }

    objects = converter.process_login_attempt(login_attempt)
    types = {_get_type(obj) for obj in objects}

    assert "ipv4-addr" in types
    assert "indicator" not in types


def test_medium_threat_with_user_creates_user_account() -> None:
    """
    Validate MEDIUM threat with user creates user-account.
    :return: None
    """
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[2]
    sys.path.append(str(repo_root / "src"))

    from connector.converter_to_stix import ConverterToStix
    from mokn.utils import LoginAttemptStatus

    converter = ConverterToStix(_DummyHelper(), _DummyConfig())
    login_attempt = {
        "ip": "4.4.4.4",
        "threat_level": "MEDIUM",
        "status": LoginAttemptStatus.COULD_LOCK.value,
        "date": datetime.now(timezone.utc).isoformat(),
        "username": "diana",
    }

    objects = converter.process_login_attempt(login_attempt)
    types = {_get_type(obj) for obj in objects}

    assert "ipv4-addr" in types
    assert "user-account" in types
