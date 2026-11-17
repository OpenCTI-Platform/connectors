from typing import Any

import pytest
import requests
from intelowl_client import IntelOwlClient, IntelOwlClientError, IntelOwlJobTimeoutError


class FakeResponse:
    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self._body = body
        self.text = str(body)

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    def json(self) -> Any:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeSession(requests.Session):
    """Records requests and answers them from a queue of responses."""

    def __init__(self, responses: list[Any]) -> None:
        super().__init__()
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(self, method, url, **kwargs):  # type: ignore[override]
        self.calls.append({"method": method, "url": url, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def make_client(responses: list[Any]) -> tuple[IntelOwlClient, FakeSession]:
    session = FakeSession(responses)
    client = IntelOwlClient(
        "https://intelowl.example.com/", "secret-key", verify_ssl=False, session=session
    )
    return client, session


@pytest.mark.parametrize(
    "body",
    [
        pytest.param([{"job_id": 42, "status": "accepted"}], id="list_response"),
        pytest.param(
            {"count": 1, "results": [{"job_id": 42, "status": "accepted"}]},
            id="results_response",
        ),
    ],
)
def test_analyze_observable_starts_the_playbook(body):
    client, session = make_client([FakeResponse(200, body)])

    job_id = client.analyze_observable(
        "198.51.100.7", "ip", "FREE_TO_USE_ANALYZERS", "AMBER", tags=["opencti"]
    )

    assert job_id == 42
    call = session.calls[0]
    assert call["method"] == "POST"
    assert (
        call["url"]
        == "https://intelowl.example.com/api/playbook/analyze_multiple_observables"
    )
    assert call["json"] == {
        "observables": [["ip", "198.51.100.7"]],
        "playbook_requested": "FREE_TO_USE_ANALYZERS",
        "tlp": "AMBER",
        "tags_labels": ["opencti"],
        "runtime_configuration": {},
    }
    assert session.headers["Authorization"] == "Token secret-key"
    assert session.verify is False


def test_analyze_observable_raises_when_intelowl_does_not_start_a_job():
    client, _ = make_client(
        [
            FakeResponse(
                200, [{"status": "not_available", "errors": {"detail": "no analyzers"}}]
            )
        ]
    )
    with pytest.raises(IntelOwlClientError, match="did not start the analysis"):
        client.analyze_observable("198.51.100.7", "ip", "PLAYBOOK", "CLEAR")


@pytest.mark.parametrize(
    "response, message",
    [
        pytest.param(
            FakeResponse(401, {"detail": "Invalid token."}), "HTTP 401", id="http_error"
        ),
        pytest.param(
            FakeResponse(200, ValueError("no json")), "non-JSON", id="not_json"
        ),
        pytest.param(
            requests.ConnectionError("refused"),
            "Could not reach IntelOwl",
            id="network",
        ),
        pytest.param(FakeResponse(200, []), "Unexpected analysis response", id="empty"),
    ],
)
def test_analyze_observable_wraps_errors(response, message):
    client, _ = make_client([response])
    with pytest.raises(IntelOwlClientError, match=message):
        client.analyze_observable("198.51.100.7", "ip", "PLAYBOOK", "CLEAR")


def test_wait_for_job_polls_until_the_job_is_reported():
    client, session = make_client(
        [
            FakeResponse(200, {"id": 42, "status": "running"}),
            FakeResponse(200, {"id": 42, "status": "analyzers_completed"}),
            FakeResponse(200, {"id": 42, "status": "reported_without_fails"}),
        ]
    )
    sleeps: list[float] = []

    job = client.wait_for_job(
        42, poll_interval=5, timeout=60, sleep=sleeps.append, clock=lambda: 0
    )

    assert job["status"] == "reported_without_fails"
    assert sleeps == [5, 5]
    assert [c["url"] for c in session.calls] == [
        "https://intelowl.example.com/api/jobs/42"
    ] * 3


def test_wait_for_job_times_out():
    client, _ = make_client([FakeResponse(200, {"id": 42, "status": "running"})] * 3)
    now = iter([0, 30, 61])

    with pytest.raises(
        IntelOwlJobTimeoutError, match="still 'running' after 60 seconds"
    ):
        client.wait_for_job(
            42,
            poll_interval=30,
            timeout=60,
            sleep=lambda _: None,
            clock=lambda: next(now),
        )


def test_job_url():
    client, _ = make_client([])
    assert client.job_url(42) == "https://intelowl.example.com/jobs/42"
