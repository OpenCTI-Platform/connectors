import queue
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import trafilatura
from connector import connector as connector_module
from connector.article import extract_article
from connector.connector import ReportArticleFetcherConnector, run_workers
from connector.settings import ReportArticleFetcherConfig

NAME = "Akira ransomware targets VPN appliances"
URL = "https://blog.example.com/akira-ransomware-vpn-appliances"
FETCH_SECONDS = 0.2
ARTICLE_HTML = (
    f"<html><head><title>{NAME}</title></head><body><article><h1>{NAME}</h1>"
    + "".join(
        f"<p>Paragraph {i} of the analysis of {NAME} and its operators.</p>"
        for i in range(40)
    )
    + "</article></body></html>"
)


def _settings(max_workers: int = 1, summary_log_level: str = "error"):
    return SimpleNamespace(
        connector=SimpleNamespace(max_tlp="amber"),
        report_article_fetcher=ReportArticleFetcherConfig(
            max_workers=max_workers, summary_log_level=summary_log_level
        ),
    )


def _report(index: int) -> dict:
    return {
        "id": f"report--{index:08d}-0000-4000-8000-000000000000",
        "type": "report",
        "name": NAME,
        "external_references": [
            {
                "source_name": NAME,
                "description": "Feed item. Retrieved 2026-11-03T10:00:00.000Z.",
                "url": URL,
            }
        ],
    }


def _message(index: int) -> dict:
    """A playbook message: no event_type, the report in the bundle."""
    report = _report(index)
    return {
        "stix_objects": [report],
        "stix_entity": report,
        "enrichment_entity": {"objectMarking": []},
        "playbook_step": f"step-{index}",
    }


class FakeHelper:
    """A pycti helper reduced to what a worker uses.

    Like the real helper, it holds the context of the message being processed
    (here `playbook`) on itself, so two messages handled by the same helper at
    the same time would overwrite each other's context.
    """

    def __init__(self, messages: queue.Queue, sent: list, lock: threading.Lock):
        self.listen_protocol = "AMQP"
        self.metric = SimpleNamespace(activated=False)
        self.connector_logger = MagicMock()
        self.playbook = None
        self._messages = messages
        self._sent = sent
        self._lock = lock

    def check_max_tlp(self, tlp, max_tlp):
        return True

    def stix2_create_bundle(self, objects):
        return objects

    def send_stix2_bundle(self, bundle):
        with self._lock:
            self._sent.append((self.playbook, bundle[0]["id"]))

    def listen(self, message_callback):
        while True:
            try:
                message = self._messages.get_nowait()
            except queue.Empty:
                return
            self.playbook = message["playbook_step"]
            message_callback(message)
            self.playbook = None


@pytest.fixture
def slow_fetch(monkeypatch):
    sessions = []

    def fetch(url, user_agent, timeout, max_size, session=None):
        sessions.append(session)
        time.sleep(FETCH_SECONDS)
        return url, ARTICLE_HTML

    monkeypatch.setattr(connector_module, "fetch_html", fetch)
    return sessions


def _run(max_workers: int, count: int):
    messages: queue.Queue = queue.Queue()
    for index in range(count):
        messages.put(_message(index))
    sent: list = []
    lock = threading.Lock()
    helpers: list = []

    def make_helper():
        helper = FakeHelper(messages, sent, lock)
        helpers.append(helper)
        return helper

    started = time.monotonic()
    run_workers(_settings(max_workers), make_helper)
    return time.monotonic() - started, sent, helpers


def test_four_workers_process_a_batch_in_about_a_quarter_of_the_time(slow_fetch):
    serial, serial_sent, _ = _run(1, 15)
    parallel, parallel_sent, helpers = _run(4, 15)

    assert len(helpers) == 4
    assert len(serial_sent) == len(parallel_sent) == 15
    # 15 fetches of 0.2 s: 3 s in a row, 4 rounds of 0.2 s with 4 workers
    assert serial >= 15 * FETCH_SECONDS
    assert parallel < serial / 2.5


def test_each_bundle_goes_back_with_its_own_playbook_context(slow_fetch):
    _, sent, _ = _run(4, 15)

    assert sorted(sent) == sorted(
        (f"step-{index}", _report(index)["id"]) for index in range(15)
    )


def test_a_worker_reuses_its_session_and_never_shares_it(slow_fetch):
    _, _, helpers = _run(4, 15)

    sessions = [session for session in slow_fetch if session is not None]
    assert len(sessions) == 15
    assert len({id(session) for session in sessions}) <= len(helpers)


def test_several_workers_require_amqp():
    helper = FakeHelper(queue.Queue(), [], threading.Lock())
    helper.listen_protocol = "API"
    with pytest.raises(ValueError, match="AMQP"):
        run_workers(_settings(2), lambda: helper)


def test_a_failed_worker_stops_the_process_with_its_error():
    def make_helper():
        helper = FakeHelper(queue.Queue(), [], threading.Lock())
        if not helpers:
            helper.listen = MagicMock(side_effect=ConnectionError("AMQP closed"))
        else:
            # a healthy worker: keeps consuming until the process stops
            helper.listen = lambda message_callback: time.sleep(30)
        helpers.append(helper)
        return helper

    helpers: list = []
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="AMQP closed"):
        run_workers(_settings(3), make_helper)
    assert time.monotonic() - started < 5


def test_one_summary_line_per_report_with_timings(slow_fetch):
    helper = FakeHelper(queue.Queue(), [], threading.Lock())
    connector = ReportArticleFetcherConnector(_settings(), helper)

    connector.process_message(_message(0))

    helper.connector_logger.error.assert_called_once()
    (title,) = helper.connector_logger.error.call_args.args
    meta = helper.connector_logger.error.call_args.kwargs["meta"]
    assert title == "Report enriched"
    assert meta["outcome"] == "enriched"
    for step in ("fetch_ms", "extract_ms", "judge_ms", "send_ms", "total_ms"):
        assert isinstance(meta[step], int)
    assert meta["fetch_ms"] >= FETCH_SECONDS * 1000 * 0.9


def test_the_summary_line_can_be_turned_off(slow_fetch):
    helper = FakeHelper(queue.Queue(), [], threading.Lock())
    connector = ReportArticleFetcherConnector(
        _settings(summary_log_level="none"), helper
    )

    connector.process_message(_message(0))

    helper.connector_logger.error.assert_not_called()


def test_extraction_parses_the_page_once(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a second extraction pass")

    monkeypatch.setattr(trafilatura, "extract", refuse)
    monkeypatch.setattr(trafilatura, "extract_metadata", refuse)

    article = extract_article(URL, ARTICLE_HTML)

    assert article is not None
    assert article.title == NAME
    assert "Paragraph 39" in article.text
    assert "<p>" in article.html
