import pytest
import requests_mock
from src.hunter_client import HunterClient


def test_query_sends_api_key_header_and_params():
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.hunter.cyborgsecurity.io/es/query",
            json={"total": 0, "results": []},
        )
        client = HunterClient("https://api.hunter.cyborgsecurity.io", "secret-key")
        client.query(actors=["TeamPCP"])

        request = m.last_request
        assert request.headers["Authorization"] == "API-Key secret-key"
        assert request.qs["indexes"] == ["cyborg_usecases"]
        assert request.qs["actors"] == ["teampcp"]  # requests_mock lowercases


def test_query_serialises_multiple_values():
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.hunter.cyborgsecurity.io/es/query",
            json={"results": [{"UUID": "x"}]},
        )
        client = HunterClient("https://api.hunter.cyborgsecurity.io", "k")
        client.query(mitre_technique_ids=["T1059.007", "T1027"])

        qs = m.last_request.qs
        assert sorted(qs["mitre_technique_ids"]) == ["t1027", "t1059.007"]


def test_query_returns_results_list():
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.hunter.cyborgsecurity.io/es/query",
            json={"total": 2, "results": [{"UUID": "a"}, {"UUID": "b"}]},
        )
        client = HunterClient("https://api.hunter.cyborgsecurity.io", "k")
        results = client.query(actors="TeamPCP")
        assert [r["UUID"] for r in results] == ["a", "b"]


def test_query_respects_max_results():
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.hunter.cyborgsecurity.io/es/query",
            json={"results": [{"UUID": str(i)} for i in range(5)]},
        )
        client = HunterClient(
            "https://api.hunter.cyborgsecurity.io", "k", max_results=2
        )
        assert len(client.query(actors="TeamPCP")) == 2


def test_query_drops_empty_filter_values():
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.hunter.cyborgsecurity.io/es/query",
            json={"results": []},
        )
        client = HunterClient("https://api.hunter.cyborgsecurity.io", "k")
        client.query(actors=None, threat_names=["", "Shai-Hulud"])

        qs = m.last_request.qs
        assert "actors" not in qs
        assert qs["threat_names"] == ["shai-hulud"]


def test_api_key_required():
    with pytest.raises(ValueError):
        HunterClient("https://api.hunter.cyborgsecurity.io", "")


def test_http_error_propagates():
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.hunter.cyborgsecurity.io/es/query",
            status_code=401,
            json={"detail": "unauthorized"},
        )
        client = HunterClient("https://api.hunter.cyborgsecurity.io", "k")
        with pytest.raises(Exception):
            client.query(actors="x")
