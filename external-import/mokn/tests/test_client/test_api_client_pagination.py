import responses


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


@responses.activate
def test_get_entities_handles_pagination() -> None:
    """
    Validate pagination handling in API client.
    :return: None
    """
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[2]
    sys.path.append(str(repo_root / "src"))

    from mokn.api_client import API_ENDPOINT, MoknApiClient

    helper = _DummyHelper()
    config = _DummyConfig()
    client = MoknApiClient(helper, config)

    first_url = f"{config.mokn.console_url}{API_ENDPOINT}"
    next_url = f"{config.mokn.console_url}/page2"

    responses.add(
        responses.POST,
        first_url,
        json={"data": [{"ip": "1.1.1.1"}], "next": next_url},
        status=200,
    )
    responses.add(
        responses.POST,
        next_url,
        json={"data": [{"ip": "2.2.2.2"}], "next": None},
        status=200,
    )

    records = client.get_entities()
    assert len(records) == 2
