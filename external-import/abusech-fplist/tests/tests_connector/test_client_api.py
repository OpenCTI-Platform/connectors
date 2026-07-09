from unittest.mock import MagicMock

from abusech_fplist_connector.client_api import ConnectorClient

# Real format returned by the Hunting API get_fplist endpoint
FPLIST_CSV = (
    "################################################################\n"
    "# abuse.ch False Positive List (JSON)                          #\n"
    "# Last updated: 2026-07-08 06:31:11 UTC                        #\n"
    "#                                                              #\n"
    "# For questions please contact contactme [at] abuse.ch         #\n"
    "################################################################\n"
    "#\n"
    '"time_stamp","removal_id","platform","entry_type","entry_value","removed_by","removal_notes"\n'
    '"2026-07-08 06:31:11","8457","ThreatFox","domain","img.thesports.com","admin","Fake IOC"\n'
    '"2026-07-06 10:46:58","8453","MalwareBazaar","sha256_hash","427f73c5ac9648b43487585882525bf83b40512d14f855c819702d45dbcbef1e","user","Is not malware. Wrong uploaded file."\n'
    '"2026-05-26 17:24:03","8232","ThreatFox","ip:port","172.67.213.117:443","admin","Fake IOC"\n'
    '"2025-02-09 21:06:53","7","MalwareBazaar","sha3_384","1fba2f1ec9888c50677a740f7899888c910c71f3473ec8485157a5ff1fa8b5c78d0c558996d9aaa484a16ed3f51792d5","user",""\n'
)


def _make_client(csv_text: str) -> ConnectorClient:
    helper = MagicMock()
    config = MagicMock()
    config.abusech_fplist.api_key.get_secret_value.return_value = "test-key"
    config.abusech_fplist.api_base_url = "https://hunting-api.abuse.ch/api/v1/"

    client = ConnectorClient(helper, config)
    response = MagicMock()
    response.text = csv_text
    client.session = MagicMock()
    client.session.post.return_value = response
    return client


def test_get_fplist_parses_real_api_format():
    client = _make_client(FPLIST_CSV)

    entries = client.get_fplist()

    assert [e["removal_id"] for e in entries] == ["8457", "8453", "8232", "7"]
    assert entries[0]["entry_type"] == "domain"
    assert entries[0]["entry_value"] == "img.thesports.com"
    assert entries[2]["entry_type"] == "ip:port"
    assert entries[2]["entry_value"] == "172.67.213.117:443"
    assert entries[3]["removal_notes"] == ""


def test_get_fplist_sends_auth_key_and_query():
    client = _make_client(FPLIST_CSV)

    client.get_fplist()

    kwargs = client.session.post.call_args.kwargs
    assert kwargs["headers"] == {"Auth-Key": "test-key"}
    assert kwargs["json"] == {"query": "get_fplist", "format": "csv"}


def test_get_fplist_skips_malformed_rows():
    client = _make_client(
        '"time_stamp","removal_id","platform","entry_type","entry_value","removed_by","removal_notes"\n'
        '"2026-07-01 10:00:00","not-a-number","ThreatFox","url","http://evil.example","admin","FP"\n'
        '"2026-07-01 10:00:00","102","ThreatFox","","http://no-type.example","admin","FP"\n'
        '"2026-07-01 10:00:00","103","ThreatFox","url","http://ok.example","admin","FP"\n'
    )

    entries = client.get_fplist()

    assert [e["removal_id"] for e in entries] == ["103"]


def test_get_fplist_empty_response_returns_empty_list():
    client = _make_client("# abuse.ch False Positive List\n# no results\n")

    assert client.get_fplist() == []
