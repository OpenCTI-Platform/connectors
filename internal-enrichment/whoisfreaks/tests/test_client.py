import pytest
import requests
import requests_mock
from client import WhoisFreaksClient

@pytest.fixture
def client():
    return WhoisFreaksClient(api_key="test-api-key", timeout=10)

def test_client_init(client):
    assert client.api_key == "test-api-key"
    assert client.timeout == 10
    assert client.session.headers["User-Agent"] == "OpenCTI-WhoisFreaks-Connector/1.0"
    assert client.session.headers["Accept"] == "application/json"

def test_client_get_success(client, requests_mock_fixture=None):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/whois/live?apiKey=test-api-key&format=json&domainName=example.com", json={"status": "success"})
        res = client.live_whois_lookup("example.com")
        assert res == {"status": "success"}

def test_client_get_404(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/whois/live?apiKey=test-api-key&format=json&domainName=example.com", status_code=404)
        res = client.live_whois_lookup("example.com")
        assert res is None

def test_client_get_401(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/whois/live?apiKey=test-api-key&format=json&domainName=example.com", status_code=401)
        res = client.live_whois_lookup("example.com")
        assert res is None

def test_client_get_429(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/whois/live?apiKey=test-api-key&format=json&domainName=example.com", status_code=429)
        res = client.live_whois_lookup("example.com")
        assert res is None

def test_client_get_500(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/whois/live?apiKey=test-api-key&format=json&domainName=example.com", status_code=500, text="Internal Server Error")
        res = client.live_whois_lookup("example.com")
        assert res is None

def test_client_get_timeout(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/whois/live?apiKey=test-api-key&format=json&domainName=example.com", exc=requests.exceptions.Timeout)
        res = client.live_whois_lookup("example.com")
        assert res is None

def test_client_get_request_exception(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/whois/live?apiKey=test-api-key&format=json&domainName=example.com", exc=requests.RequestException)
        res = client.live_whois_lookup("example.com")
        assert res is None

def test_client_post_success(client):
    with requests_mock.Mocker() as m:
        m.post("https://api.whoisfreaks.com/v2.0/bulkwhois/live?apiKey=test-api-key&format=json", json={"bulk": "success"})
        res = client.bulk_whois_lookup(["example.com"])
        assert res == {"bulk": "success"}
        assert m.last_request.json() == {"domainNames": ["example.com"]}

def test_client_post_error(client):
    with requests_mock.Mocker() as m:
        m.post("https://api.whoisfreaks.com/v2.0/bulkwhois/live?apiKey=test-api-key&format=json", status_code=500)
        res = client.bulk_whois_lookup(["example.com"])
        assert res is None

def test_client_post_timeout(client):
    with requests_mock.Mocker() as m:
        m.post("https://api.whoisfreaks.com/v2.0/bulkwhois/live?apiKey=test-api-key&format=json", exc=requests.exceptions.Timeout)
        res = client.bulk_whois_lookup(["example.com"])
        assert res is None

def test_client_post_exception(client):
    with requests_mock.Mocker() as m:
        m.post("https://api.whoisfreaks.com/v2.0/bulkwhois/live?apiKey=test-api-key&format=json", exc=requests.RequestException)
        res = client.bulk_whois_lookup(["example.com"])
        assert res is None

# Tests for all endpoint wrappers to ensure correctness of URL mappings and HTTP verbs

def test_historical_whois_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/whois?apiKey=test-api-key&format=json&domainName=example.com&whois=historical", json={"data": "whois"})
        assert client.historical_whois_lookup("example.com") == {"data": "whois"}

def test_reverse_whois_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v1.0/whois?apiKey=test-api-key&format=json&keyword=example&whois=reverse", json={"data": "rev"})
        assert client.reverse_whois_lookup("example") == {"data": "rev"}

def test_live_dns_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/dns/live?apiKey=test-api-key&format=json&domainName=example.com&type=all", json={"data": "dns"})
        assert client.live_dns_lookup("example.com") == {"data": "dns"}

def test_historical_dns_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/dns/historical?apiKey=test-api-key&format=json&domainName=example.com&type=all&page=2", json={"data": "hist"})
        assert client.historical_dns_lookup("example.com", page=2) == {"data": "hist"}

def test_reverse_dns_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/dns/reverse?apiKey=test-api-key&format=json&value=1.2.3.4&page=1&type=a&exact=True", json={"data": "rev"})
        assert client.reverse_dns_lookup("1.2.3.4") == {"data": "rev"}

def test_bulk_dns_lookup(client):
    with requests_mock.Mocker() as m:
        m.post("https://api.whoisfreaks.com/v2.0/dns/bulk/live?apiKey=test-api-key&format=json&type=all", json={"data": "bulk"})
        assert client.bulk_dns_lookup(["example.com"], ["1.2.3.4"]) == {"data": "bulk"}

def test_domain_availability_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v1.0/domain/availability?apiKey=test-api-key&format=json&domainName=example.com&sug=False", json={"data": "avail"})
        assert client.domain_availability_lookup("example.com") == {"data": "avail"}

def test_bulk_domain_availability_lookup(client):
    with requests_mock.Mocker() as m:
        m.post("https://api.whoisfreaks.com/v1.0/domain/availability?apiKey=test-api-key&format=json", json={"data": "bulk_avail"})
        assert client.bulk_domain_availability_lookup(["example.com"]) == {"data": "bulk_avail"}

def test_typosquatting_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v3.0/domain/tyops?apiKey=test-api-key&keyword=example", json={"data": "typo"})
        # Note: in client.py line 188: self._get("/v3.0/domain/typos", params={"keyword": keyword})
        # Wait, the path is typos, let's fix URL mock:
        m.get("https://api.whoisfreaks.com/v3.0/domain/typos?apiKey=test-api-key&keyword=example", json={"data": "typo"})
        assert client.typosquatting_lookup("example") == {"data": "typo"}

def test_ssl_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v1.0/ssl/live?apiKey=test-api-key&format=json&domainName=example.com&chain=True&sslRaw=False", json={"data": "ssl"})
        assert client.ssl_lookup("example.com") == {"data": "ssl"}

def test_ip_geolocation_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v1.0/geolocation?apiKey=test-api-key&format=json&ip=1.2.3.4", json={"data": "geo"})
        assert client.ip_geolocation_lookup("1.2.3.4") == {"data": "geo"}

def test_bulk_ip_geolocation_lookup(client):
    with requests_mock.Mocker() as m:
        m.post("https://api.whoisfreaks.com/v1.0/geolocation?apiKey=test-api-key", json={"data": "bulk_geo"})
        assert client.bulk_ip_geolocation_lookup(["1.2.3.4"]) == {"data": "bulk_geo"}

def test_subdomains_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v1.0/subdomains?apiKey=test-api-key&format=json&domain=example.com&page=2", json={"data": "sub"})
        assert client.subdomains_lookup("example.com", page=2) == {"data": "sub"}

def test_ip_reputation_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v1.0/security?apiKey=test-api-key&ip=1.2.3.4", json={"data": "rep"})
        assert client.ip_reputation_lookup("1.2.3.4") == {"data": "rep"}

def test_bulk_ip_reputation_lookup(client):
    with requests_mock.Mocker() as m:
        m.post("https://api.whoisfreaks.com/v1.0/security?apiKey=test-api-key", json={"data": "bulk_rep"})
        assert client.bulk_ip_reputation_lookup(["1.2.3.4"]) == {"data": "bulk_rep"}

def test_asn_whois_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v2.0/asn-whois?apiKey=test-api-key&asn=AS15169&format=json", json={"data": "asn"})
        assert client.asn_whois_lookup("AS15169") == {"data": "asn"}

def test_ip_whois_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v1.0/ip-whois?apiKey=test-api-key&ip=1.2.3.4&format=json", json={"data": "ip_whois"})
        assert client.ip_whois_lookup("1.2.3.4") == {"data": "ip_whois"}

def test_domain_reputation_lookup(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v1.0/domain-reputation?apiKey=test-api-key&domainName=example.com&format=json", json={"data": "dom_rep"})
        assert client.domain_reputation_lookup("example.com") == {"data": "dom_rep"}

def test_account_usage(client):
    with requests_mock.Mocker() as m:
        m.get("https://api.whoisfreaks.com/v1.0/whoisapi/usage?apiKey=test-api-key", json={"data": "usage"})
        assert client.account_usage() == {"data": "usage"}

def test_rotate_api_key(client):
    with requests_mock.Mocker() as m:
        m.post("https://api.whoisfreaks.com/v1.0/api-key/rotate?apiKey=test-api-key", json={"data": "rotate"})
        assert client.rotate_api_key() == {"data": "rotate"}
