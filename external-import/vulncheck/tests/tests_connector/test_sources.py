"""End-to-end-ish test of a source's collect_* flow (with mocked client/works)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import connector.util.works as works
from connector.converter_to_stix import ConverterToStix
from connector.sources.botnets import collect_botnets


def test_collect_botnets_builds_and_sends_bundle(settings, helper, monkeypatch):
    sent = []
    monkeypatch.setattr(works, "start_work", lambda **kwargs: "work-1")
    monkeypatch.setattr(works, "finish_work", lambda **kwargs: None)
    monkeypatch.setattr(
        works, "send_bundle", lambda **kwargs: sent.append(kwargs["stix_objects"])
    )

    # settings scope is "vulnerability,software" -> only the vulnerability path is in scope
    entity = SimpleNamespace(
        botnet_name="Mirai",
        cve=["CVE-2024-0001"],
        date_added="2024-01-01T00:00:00",
    )
    client = MagicMock()
    client.iter_botnets.return_value = [[entity]]

    collect_botnets(settings, helper, client, ConverterToStix(helper), MagicMock(), {})

    assert sent, "expected at least one bundle to be sent"
    types = {obj.type for obj in sent[0]}
    assert "vulnerability" in types


def test_collect_botnets_skips_when_out_of_scope(monkeypatch, helper):
    """A connector scope that shares nothing with the source scope -> skip."""
    started = []
    monkeypatch.setattr(works, "start_work", lambda **kwargs: started.append(1))

    config = SimpleNamespace(connector=SimpleNamespace(scope=["malware"]))
    client = MagicMock()

    collect_botnets(config, helper, client, MagicMock(), MagicMock(), {})

    client.iter_botnets.assert_not_called()
    assert not started
