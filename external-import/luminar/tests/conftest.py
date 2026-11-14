import json
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest
import requests

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

TS = "2026-01-01T00:00:00.000Z"
EXT = "extension-definition--ddd2bf71-3c91-5f4d-8251-10cd685737c3"


def stix_id(stix_type: str, number: int) -> str:
    """Deterministic, valid STIX id for synthetic test objects."""
    return f"{stix_type}--00000000-0000-4000-8000-{number:012d}"


class RecordingLogger:
    """Stand-in for the OpenCTI connector_logger (message, meta) interface."""

    def __init__(self) -> None:
        self.records: List[Tuple[str, str, Optional[Dict]]] = []

    def _record(self, level: str, message: str, meta: Optional[Dict] = None) -> None:
        self.records.append((level, message, meta))

    def debug(self, message, meta=None):
        self._record("debug", message, meta)

    def info(self, message, meta=None):
        self._record("info", message, meta)

    def warning(self, message, meta=None):
        self._record("warning", message, meta)

    def error(self, message, meta=None):
        self._record("error", message, meta)

    def messages(self, level: Optional[str] = None) -> List[str]:
        return [m for lvl, m, _ in self.records if level is None or lvl == level]


class FakeResponse:
    """Minimal requests.Response stand-in."""

    def __init__(
        self,
        status: int = 200,
        body: Any = None,
        headers: Optional[Dict[str, str]] = None,
        reason: str = "OK",
        raw: Optional[bytes] = None,
    ) -> None:
        self.status_code = status
        self.headers = headers or {}
        self.reason = reason
        self._body = body
        if raw is not None:
            self.content = raw
        elif body is None:
            self.content = b""
        else:
            self.content = json.dumps(body).encode()

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    def json(self) -> Any:
        return json.loads(self.content)


class FakeTaxiiServer:
    """Scripted Luminar API: token, collections, paginated objects, match[id].

    ``pages`` is a list of object lists; the ``next`` cursor is the page index.
    ``scripted`` maps a call number of the objects endpoint (0-based, counting
    every objects request) to a FakeResponse or an exception to raise instead.
    """

    def __init__(
        self,
        pages: Optional[List[List[Dict[str, Any]]]] = None,
        store: Optional[Dict[str, Dict[str, Any]]] = None,
        collections: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.pages = pages or []
        self.store = dict(store or {})
        for page in self.pages:
            for obj in page:
                self.store.setdefault(obj["id"], obj)
        self.collections = (
            collections
            if collections is not None
            else [
                {"alias": "iocs", "id": "c-iocs"},
                {"alias": "leakedrecords", "id": "c-leaked"},
                {"alias": "cyberfeeds", "id": "c-cyber"},
                {"alias": "vulnerabilities", "id": "c-vulns"},
            ]
        )
        self.token_responses: List[Any] = []
        self.collection_responses: List[Any] = []
        self.scripted: Dict[int, Any] = {}
        self.match_responses: List[Any] = []
        self.object_calls: List[Dict[str, Any]] = []
        self.match_calls: List[List[str]] = []

    @staticmethod
    def _resolve(item: Any) -> FakeResponse:
        if isinstance(item, BaseException):
            raise item
        return item

    def token(self) -> FakeResponse:
        if self.token_responses:
            return self._resolve(self.token_responses.pop(0))
        return FakeResponse(200, {"access_token": "test-token"})

    def collections_response(self) -> FakeResponse:
        if self.collection_responses:
            return self._resolve(self.collection_responses.pop(0))
        return FakeResponse(200, {"collections": self.collections})

    def objects(self, params: Dict[str, Any]) -> FakeResponse:
        if "match[id]" in params:
            ids = params["match[id]"].split(",")
            self.match_calls.append(ids)
            if self.match_responses:
                return self._resolve(self.match_responses.pop(0))
            return FakeResponse(
                200, {"objects": [self.store[i] for i in ids if i in self.store]}
            )
        call = len(self.object_calls)
        self.object_calls.append(dict(params))
        if call in self.scripted:
            return self._resolve(self.scripted[call])
        index = int(params.get("next") or 0)
        if index >= len(self.pages):
            return FakeResponse(200, {"objects": []})
        body: Dict[str, Any] = {"objects": self.pages[index]}
        if index + 1 < len(self.pages):
            body["next"] = str(index + 1)
        headers = {
            "X-TAXII-Date-Added-First": f"2026-01-01T00:00:{index:02d}.000000Z",
            "X-TAXII-Date-Added-Last": f"2026-01-01T00:00:{index:02d}.500000Z",
        }
        return FakeResponse(200, body, headers)


class FakeSession:
    """requests.Session stand-in routing calls to a FakeTaxiiServer."""

    def __init__(self, server: FakeTaxiiServer) -> None:
        self.server = server
        self.headers: Dict[str, str] = {}

    def post(self, url, headers=None, data=None, timeout=None):
        assert url.endswith("/token")
        return self.server.token()

    def get(self, url, params=None, timeout=None):
        if url.endswith("/collections/"):
            return self.server.collections_response()
        return self.server.objects(params or {})


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Retry and polling delays must never slow the test suite down."""
    import luminar_connector.connector as connector_module
    import luminar_connector.luminar_manager as manager_module

    monkeypatch.setattr(manager_module.time, "sleep", lambda *_: None)
    monkeypatch.setattr(connector_module.time, "sleep", lambda *_: None)


@pytest.fixture
def logger() -> RecordingLogger:
    return RecordingLogger()


@pytest.fixture
def taxii_server() -> FakeTaxiiServer:
    return FakeTaxiiServer()


@pytest.fixture
def make_manager(logger) -> Callable[..., Any]:
    """Build a LuminarManager whose HTTP session talks to a FakeTaxiiServer."""
    from luminar_connector.luminar_manager import LuminarManager

    def _make(server: FakeTaxiiServer, **kwargs: Any) -> LuminarManager:
        kwargs.setdefault("added_after", "2026-01-01T00:00:00.000000Z")
        manager = LuminarManager(
            "client-id",
            "client-secret",
            "account-id",
            "https://luminar.test/",
            logger=logger,
            **kwargs,
        )
        manager.session = FakeSession(server)
        return manager

    return _make


@pytest.fixture
def network_error() -> requests.RequestException:
    return requests.ConnectionError("connection reset")
