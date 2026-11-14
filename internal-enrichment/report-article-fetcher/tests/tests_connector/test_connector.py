from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector import connector as connector_module
from connector.article import Article, FetchError, Verdict
from connector.connector import STIX_EXT_OCTI, ReportArticleFetcherConnector

NAME = "Akira ransomware targets VPN appliances"
URL = "https://blog.example.com/akira-ransomware-vpn-appliances"
REPORT = {
    "id": "report--3b4f6a7e-6d7c-4a7c-9a1f-0e1f2a3b4c5d",
    "type": "report",
    "name": NAME,
    "external_references": [
        {
            "source_name": NAME,
            "description": f"Feed {NAME}. Retrieved 2026-11-03T10:00:00.000Z.",
            "url": URL,
        }
    ],
}
AUTHOR = {"id": "identity--1d1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b", "type": "identity"}
ARTICLE = Article(url=URL, title=NAME, html="<p>body</p>", text="body " * 200)


def _connector(max_tlp="amber"):
    helper = MagicMock()
    helper.check_max_tlp.return_value = True
    helper.stix2_create_bundle.side_effect = lambda objects: {"objects": objects}
    config = SimpleNamespace(
        connector=SimpleNamespace(max_tlp=max_tlp),
        report_article_fetcher=SimpleNamespace(
            user_agent="test",
            request_timeout=5,
            max_download_size=1000,
            min_length=500,
            length_ratio=1.5,
            min_title_similarity=0.6,
            match_single_reference=False,
        ),
    )
    return ReportArticleFetcherConnector(config=config, helper=helper), helper


def _message(report=None, playbook=False, markings=None):
    report = report or REPORT
    data = {
        "stix_objects": [report, AUTHOR],
        "stix_entity": report,
        "enrichment_entity": {"objectMarking": markings},
    }
    if not playbook:
        data["event_type"] = "INTERNAL_ENRICHMENT"
    return data


@pytest.fixture
def fetched(monkeypatch):
    """The page is fetched, extracted and accepted unless a test says otherwise."""
    monkeypatch.setattr(
        connector_module, "fetch_html", lambda url, **_: (url, "<html></html>")
    )
    monkeypatch.setattr(connector_module, "extract_article", lambda url, html: ARTICLE)
    monkeypatch.setattr(
        connector_module, "judge", lambda *_, **__: Verdict(True, "1000 characters")
    )


def _sent_objects(helper):
    return helper.send_stix2_bundle.call_args.args[0]["objects"]


def test_writes_the_article_to_the_report_content(fetched):
    connector, helper = _connector()
    message = connector.process_message(_message())

    assert message.startswith("Article written to the report")
    sent = _sent_objects(helper)
    assert sent[0]["extensions"][STIX_EXT_OCTI]["content"] == ARTICLE.html
    assert sent[0]["extensions"][STIX_EXT_OCTI]["extension_type"] == (
        "property-extension"
    )
    assert sent[1] == AUTHOR
    # The report received is never changed in place
    assert "extensions" not in REPORT


def test_keeps_the_other_extension_fields(fetched):
    report = dict(
        REPORT, extensions={STIX_EXT_OCTI: {"id": "x", "content": "<p>teaser</p>"}}
    )
    connector, helper = _connector()
    connector.process_message(_message(report))

    extension = _sent_objects(helper)[0]["extensions"][STIX_EXT_OCTI]
    assert extension == {"id": "x", "content": ARTICLE.html}
    assert report["extensions"][STIX_EXT_OCTI]["content"] == "<p>teaser</p>"


def test_skipped_in_a_playbook_still_sends_the_bundle(fetched, monkeypatch):
    monkeypatch.setattr(
        connector_module, "judge", lambda *_, **__: Verdict(False, "too short")
    )
    connector, helper = _connector()
    message = connector.process_message(_message(playbook=True))

    assert message == "Skipped: too short"
    assert _sent_objects(helper) == [REPORT, AUTHOR]


def test_skipped_outside_a_playbook_sends_nothing(fetched, monkeypatch):
    monkeypatch.setattr(
        connector_module, "judge", lambda *_, **__: Verdict(False, "too short")
    )
    connector, helper = _connector()
    assert connector.process_message(_message()) == "Skipped: too short"
    helper.send_stix2_bundle.assert_not_called()


def test_refuses_a_report_above_the_max_tlp(fetched):
    connector, helper = _connector(max_tlp="green")
    helper.check_max_tlp.return_value = False
    markings = [{"definition_type": "TLP", "definition": "TLP:RED"}]

    message = connector.process_message(_message(markings=markings))

    assert message.startswith("Not enriched: TLP")
    helper.check_max_tlp.assert_called_once_with("TLP:RED", "TLP:GREEN")
    helper.send_stix2_bundle.assert_not_called()


def test_reads_a_null_marking_list_as_no_marking(fetched):
    connector, helper = _connector()
    connector.process_message(_message(markings=None))
    helper.check_max_tlp.assert_called_once_with(None, "TLP:AMBER")


def test_ignores_markings_that_are_not_tlp(fetched):
    connector, helper = _connector()
    markings = [
        {"definition_type": "PAP", "definition": "PAP:RED"},
        {"definition_type": "TLP", "definition": "TLP:GREEN"},
    ]
    connector.process_message(_message(markings=markings))
    helper.check_max_tlp.assert_called_once_with("TLP:GREEN", "TLP:AMBER")


def test_refuses_an_entity_that_is_not_a_report(fetched):
    connector, helper = _connector()
    note = {"id": "note--1", "type": "note"}
    assert (
        connector.process_message(_message(note))
        == "Not enriched: note is not a report"
    )
    helper.send_stix2_bundle.assert_not_called()


def test_an_error_in_a_playbook_still_sends_the_bundle(monkeypatch):
    def fail(*_, **__):
        raise RuntimeError("boom")

    monkeypatch.setattr(connector_module, "fetch_html", fail)
    connector, helper = _connector()
    message = connector.process_message(_message(playbook=True))

    assert message == "Not enriched: boom"
    assert _sent_objects(helper) == [REPORT, AUTHOR]


def test_skips_a_report_without_an_article_reference(fetched):
    report = dict(REPORT, external_references=[])
    connector, _ = _connector()
    enriched, message = connector._enrich(report)
    assert enriched is None
    assert message.startswith("Skipped: 0 article reference(s)")


def test_skips_a_page_that_cannot_be_fetched(fetched, monkeypatch):
    def refuse(*_, **__):
        raise FetchError("HTTP 404")

    monkeypatch.setattr(connector_module, "fetch_html", refuse)
    connector, _ = _connector()
    assert connector._enrich(REPORT) == (None, "Skipped: HTTP 404")


def test_skips_a_page_without_an_article(fetched, monkeypatch):
    monkeypatch.setattr(connector_module, "extract_article", lambda *_: None)
    connector, _ = _connector()
    assert connector._enrich(REPORT) == (
        None,
        "Skipped: no article body found in the page",
    )


def test_passes_the_current_content_text_to_the_verdict(fetched, monkeypatch):
    seen = {}

    def judge(article, **kwargs):
        seen.update(kwargs)
        return Verdict(False, "not longer")

    monkeypatch.setattr(connector_module, "judge", judge)
    report = dict(
        REPORT, extensions={STIX_EXT_OCTI: {"content": "<p>Some&nbsp;teaser</p>"}}
    )
    connector, _ = _connector()
    connector._enrich(report)
    assert seen["current_content"] == "Some teaser"
    assert seen["report_name"] == NAME
    assert seen["min_length"] == 500


def test_run_listens_with_process_message():
    connector, helper = _connector()
    connector.run()
    helper.listen.assert_called_once_with(message_callback=connector.process_message)
