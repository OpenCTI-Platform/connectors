from datetime import datetime

import pytest
import requests
from tweetfeed import TweetFeed

# ---------------------------------------------------------------------------
# _generate_path
# ---------------------------------------------------------------------------


def test_generate_path_returns_today_csv_for_current_date():
    today = datetime.now().strftime("%Y%m%d")
    url = TweetFeed._generate_path(today)
    assert (
        url
        == "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/today.csv"
    )


def test_generate_path_returns_correct_url_for_past_date():
    url = TweetFeed._generate_path("20260609")
    assert (
        url
        == "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/2026/202606/20260609.csv"
    )


def test_generate_path_returns_correct_url_across_months():
    url = TweetFeed._generate_path("20260501")
    assert (
        url
        == "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/2026/202605/20260501.csv"
    )


def test_generate_path_returns_correct_url_across_years():
    url = TweetFeed._generate_path("20251231")
    assert (
        url
        == "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/2025/202512/20251231.csv"
    )


# ---------------------------------------------------------------------------
# _validate_ipv4
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "1.2.3.4",
        "0.0.0.0",
        "255.255.255.255",
        "192.168.1.100",
        "10.0.0.1",
    ],
)
def test_validate_ipv4_accepts_valid_addresses(ip):
    assert TweetFeed._validate_ipv4(ip)


@pytest.mark.parametrize(
    "ip",
    [
        "256.0.0.1",
        "1.2.3",
        "1.2.3.4.5",
        "1.2.3.4/24",
        "not-an-ip",
        "",
        "1.2.3.",
    ],
)
def test_validate_ipv4_rejects_invalid_addresses(ip):
    assert not TweetFeed._validate_ipv4(ip)


# ---------------------------------------------------------------------------
# _validate_domain
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "domain",
    [
        "example.com",
        "sub.example.com",
        "xn--nxasmq6b.com",
        "my-domain.co.uk",
    ],
)
def test_validate_domain_accepts_valid_domains(domain):
    assert TweetFeed._validate_domain(domain)


@pytest.mark.parametrize(
    "domain",
    [
        "-invalid.com",
        "no-tld",
        "http://example.com",
        "",
        "example",
    ],
)
def test_validate_domain_rejects_invalid_domains(domain):
    assert not TweetFeed._validate_domain(domain)


# ---------------------------------------------------------------------------
# _validate_urls
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com/path",
        "https://example.com/path?q=1&r=2",
    ],
)
def test_validate_urls_accepts_valid_urls(url):
    assert TweetFeed._validate_urls(url)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "example.com",
        "http://",
        "",
    ],
)
def test_validate_urls_rejects_invalid_urls(url):
    assert not TweetFeed._validate_urls(url)


# ---------------------------------------------------------------------------
# _validate_sha256
# ---------------------------------------------------------------------------


def test_validate_sha256_accepts_valid_hash():
    valid = "a" * 64
    assert TweetFeed._validate_sha256(valid)


def test_validate_sha256_accepts_mixed_case():
    valid = "A" * 32 + "f" * 32
    assert TweetFeed._validate_sha256(valid)


@pytest.mark.parametrize(
    "h",
    [
        "a" * 63,
        "a" * 65,
        "g" * 64,
        "",
    ],
)
def test_validate_sha256_rejects_invalid_hash(h):
    assert not TweetFeed._validate_sha256(h)


# ---------------------------------------------------------------------------
# _validate_md5
# ---------------------------------------------------------------------------


def test_validate_md5_accepts_valid_hash():
    valid = "b" * 32
    assert TweetFeed._validate_md5(valid)


@pytest.mark.parametrize(
    "h",
    [
        "b" * 31,
        "b" * 33,
        "z" * 32,
        "",
    ],
)
def test_validate_md5_rejects_invalid_hash(h):
    assert not TweetFeed._validate_md5(h)


# ---------------------------------------------------------------------------
# download_ioc_file
# ---------------------------------------------------------------------------


@pytest.fixture
def tweetfeed_instance():
    """Instantiate TweetFeed without calling __init__ to avoid heavy dependencies."""
    instance = TweetFeed.__new__(TweetFeed)
    instance.session = requests.Session()
    return instance


def test_download_ioc_file_returns_content_on_200(tweetfeed_instance, requests_mock):
    url = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/today.csv"
    expected = b"2026-06-10,user,ip,1.2.3.4,#phishing,https://x.com/1"
    requests_mock.get(url, content=expected, status_code=200)

    result = tweetfeed_instance.download_ioc_file(url)

    assert result == expected


def test_download_ioc_file_returns_empty_bytes_on_404(
    tweetfeed_instance, requests_mock
):
    url = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/2026/202601/20260101.csv"
    requests_mock.get(url, status_code=404)

    result = tweetfeed_instance.download_ioc_file(url)

    assert result == b""


def test_download_ioc_file_returns_empty_bytes_on_network_error(
    tweetfeed_instance, requests_mock
):
    url = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/today.csv"
    requests_mock.get(url, exc=requests.exceptions.ConnectionError)

    result = tweetfeed_instance.download_ioc_file(url)

    assert result == b""
