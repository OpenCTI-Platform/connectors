"""Find, fetch, extract and check the article behind an RSS report.

Every function here is free of OpenCTI calls, so it can be tested and
evaluated on real feeds without a platform.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass
from difflib import SequenceMatcher
from html import unescape
from urllib.parse import urljoin, urlparse

import lxml.etree
import lxml.html
import requests
import trafilatura
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

# The OpenCTI RSS ingestion writes the article link as the report's external
# reference: source_name is the item title (the report name) and description
# is "<feed name> <item title>. Retrieved <ISO date>."
_RSS_REFERENCE_DESCRIPTION = re.compile(r"\. Retrieved \d{4}-\d{2}-\d{2}T[\d:.]+Z\.$")

# Pages served instead of the article: anti-bot challenges, consent walls.
_BLOCKED_MARKERS = (
    "just a moment",
    "attention required",
    "verify you are human",
    "are you a robot",
    "enable javascript and cookies",
    "please enable javascript",
    "access denied",
    "request blocked",
    "captcha",
    "checking your browser",
    "ddos protection by",
    "cloudflare ray id",
)

_HTML_TYPES = ("text/html", "application/xhtml+xml")
# A stub page that only redirects: <meta http-equiv="refresh" content="0;URL='...'">
_META_REFRESH = re.compile(
    r"<meta[^>]+http-equiv=[\"']?refresh[^>]+url=['\"]?([^'\">\s]+)", re.IGNORECASE
)
_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class FetchError(Exception):
    """The page could not be fetched, or fetching it is not allowed."""


@dataclass
class Article:
    """The body of an article page."""

    url: str
    title: str | None
    html: str
    text: str


@dataclass
class Verdict:
    """Whether an extracted article may replace the report's text."""

    accepted: bool
    reason: str


def html_to_text(html: str | None) -> str:
    """Strip tags and collapse whitespace, to compare text lengths."""
    if not html:
        return ""
    text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", unescape(text)).strip()


def find_article_reference(report: dict, match_single_reference: bool) -> dict:
    """Return the external reference that holds the report's article link.

    The reference written by the RSS ingestion is recognised by its
    signature. When ``match_single_reference`` is set, a report with exactly
    one external reference is accepted too, whatever created it.
    Raises ValueError when there is no candidate or more than one.
    """
    references = [
        reference
        for reference in report.get("external_references", [])
        if str(reference.get("url", "")).lower().startswith(("http://", "https://"))
    ]
    candidates = [
        reference
        for reference in references
        if reference.get("source_name") == report.get("name")
        and _RSS_REFERENCE_DESCRIPTION.search(reference.get("description") or "")
    ]
    if not candidates and match_single_reference and len(references) == 1:
        candidates = references
    if len(candidates) != 1:
        raise ValueError(
            f"{len(candidates)} article reference(s) found, exactly one expected"
        )
    return candidates[0]


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def check_public_url(url: str) -> None:
    """Refuse URLs that would make the connector reach an internal address.

    The links come from third-party feeds: without this check, a feed could
    point the connector at the platform, its database or a cloud metadata
    endpoint. Every address the host resolves to must be public.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise FetchError(f"Unsupported URL: {url}")
    try:
        port = parsed.port
    except ValueError as err:
        raise FetchError(f"Invalid port in URL: {url}") from err
    try:
        infos = socket.getaddrinfo(parsed.hostname, port or None)
    except socket.gaierror as err:
        raise FetchError(f"Cannot resolve {parsed.hostname}") from err
    for info in infos:
        if not _is_public(info[4][0]):
            raise FetchError(f"{parsed.hostname} resolves to a non-public address")


class _PublicPeer:
    """Check the address the socket actually connected to.

    check_public_url resolves the host before the request, and the request
    resolves it again: a DNS server that answers a public address first and
    an internal one next (DNS rebinding) would pass the check. Checking the
    connected socket closes that gap.
    """

    def _new_conn(self):
        sock = super()._new_conn()
        if not _is_public(sock.getpeername()[0]):
            sock.close()
            raise FetchError(f"{self.host} connected to a non-public address")
        return sock


class _PublicHTTPConnection(_PublicPeer, HTTPConnection):
    pass


class _PublicHTTPSConnection(_PublicPeer, HTTPSConnection):
    pass


class _PublicHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PublicHTTPConnection


class _PublicHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PublicHTTPSConnection


class _PublicAdapter(HTTPAdapter):
    """Connect directly to public addresses only.

    Through a proxy, the socket's peer is the proxy, which may well be
    internal: the proxy resolves the host, so only check_public_url applies.
    """

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": _PublicHTTPConnectionPool,
            "https": _PublicHTTPSConnectionPool,
        }


def fetch_html(
    url: str, user_agent: str, timeout: int, max_size: int
) -> tuple[str, str]:
    """Download an HTML page over plain HTTP. Returns (final URL, HTML).

    Redirects are followed by hand so that every hop is checked.
    """
    session = requests.Session()
    session.mount("http://", _PublicAdapter())
    session.mount("https://", _PublicAdapter())
    session.headers.update(
        {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
    )
    for _ in range(_MAX_REDIRECTS + 1):
        check_public_url(url)
        try:
            response = session.get(
                url, timeout=timeout, stream=True, allow_redirects=False
            )
        except requests.RequestException as err:
            raise FetchError(f"Request failed: {err}") from err
        with response:
            # requests' is_redirect is false on a 3xx without Location: test
            # the status, so that such a reply is refused for what it is.
            if response.status_code in _REDIRECT_STATUSES:
                location = (response.headers.get("Location") or "").strip()
                if not location:
                    raise FetchError("Redirect without Location")
                url = urljoin(url, location)
                continue
            if response.status_code != 200:
                raise FetchError(f"HTTP {response.status_code}")
            content_type = response.headers.get("Content-Type", "").lower()
            if not content_type.startswith(_HTML_TYPES):
                raise FetchError(f"Not an HTML page: {content_type or 'unknown'}")
            declared_size = response.headers.get("Content-Length", "")
            if declared_size.isdigit() and int(declared_size) > max_size:
                raise FetchError(f"Page larger than {max_size} bytes")
            body = bytearray()
            for chunk in response.iter_content(65536):
                body.extend(chunk)
                if len(body) > max_size:
                    raise FetchError(f"Page larger than {max_size} bytes")
            html = _decode(bytes(body), content_type)
            refresh = _META_REFRESH.search(html) if len(html) < 4096 else None
            if refresh:
                url = urljoin(url, refresh.group(1))
                continue
            return url, html
    raise FetchError("Too many redirects")


def _decode(body: bytes, content_type: str) -> str:
    """Decode with the declared charset: header, then <meta>, else UTF-8.

    requests falls back to ISO-8859-1 for any text/html without a charset in
    the header, which garbles accented text served as UTF-8.
    """
    declared = re.search(r"charset=([\w-]+)", content_type) or re.search(
        rb"<meta[^>]+charset=[\"']?([\w-]+)", body[:4096], re.IGNORECASE
    )
    encoding = "utf-8"
    if declared:
        value = declared.group(1)
        encoding = value.decode("ascii") if isinstance(value, bytes) else value
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def extract_article(url: str, html: str) -> Article | None:
    """Keep the article body: no menus, footers, cookie banners or comments.

    Tables, lists, code blocks and links are kept: indicators often sit
    there.
    """
    html = _prepare(html)
    options = {
        "url": url,
        "include_tables": True,
        "include_formatting": True,
        "include_links": True,
        # No images: their URLs would be fetched by whatever renders the
        # content later (the PDF export), outside the public-address checks.
        "include_images": False,
        "include_comments": False,
        "favor_recall": True,
    }
    body = trafilatura.extract(html, output_format="html", **options)
    if not body:
        return None
    text = trafilatura.extract(html, output_format="txt", **options) or ""
    metadata = trafilatura.extract_metadata(html, default_url=url)
    title = metadata.title if metadata else None
    return Article(url=url, title=title, html=_strip_document(body), text=text)


# One indicator alone in an element: a hash, an IPv4, a URL or a domain,
# defanged ("hxxp", "[.]", "[:]") or not.
_INDICATOR = re.compile(
    r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}"
    r"|(?:\d{1,3}(?:\.|\[\.\])){3}\d{1,3}"
    r"|h(?:tt|xx)ps?(?::|\[:\])//\S+"
    r"|(?:[\w-]+(?:\.|\[\.\]))+[a-z]{2,})$",
    re.IGNORECASE,
)


def _prepare(html: str) -> str:
    """Rework the layouts that make trafilatura drop indicators.

    - Tables inside a chain of <div>s that only wrap them (Google Docs
      exports): trafilatura drops tables that deep, and the indicators of
      the Google Threat Intelligence posts were lost that way. Each table
      is lifted out of its wrappers.
    - Tables inside an "embed" block (Webflow's w-embed, Team Cymru):
      trafilatura discards any element whose class mentions "embed". The
      class is dropped from the ancestors of each table.
    - Indicators listed one per bare <div> (AhnLab ASEC): trafilatura takes
      the short blocks for page chrome. Such a run of <div>s becomes a list.
    """
    try:
        document = lxml.html.fromstring(html)
    except (lxml.etree.ParserError, ValueError):
        return html
    changed = False
    for table in list(document.iter("table")):
        wrapper = table.getparent()
        while (
            wrapper is not None
            and wrapper.tag == "div"
            and len(wrapper) == 1
            and not (wrapper.text or "").strip()
            and wrapper.getparent() is not None
        ):
            parent = wrapper.getparent()
            table.tail = wrapper.tail
            parent.replace(wrapper, table)
            changed = True
            wrapper = parent
    for table in list(document.iter("table")):
        for ancestor in table.iterancestors():
            classes = (ancestor.get("class") or "").split()
            kept = [name for name in classes if "embed" not in name.lower()]
            if kept != classes:
                ancestor.set("class", " ".join(kept))
                changed = True
    for container in document.xpath("//div[div]"):
        items = list(container)
        if items and all(
            item.tag == "div"
            and len(item) == 0
            and _INDICATOR.match((item.text or "").strip())
            for item in items
        ):
            container.tag = "ul"
            for item in items:
                item.tag = "li"
            changed = True
    if not changed:
        return html
    return lxml.html.tostring(document, encoding="unicode")


def _strip_document(html: str) -> str:
    """trafilatura wraps its HTML in <html><body>: keep the inside only."""
    match = re.search(r"<body[^>]*>(.*)</body>", html, re.DOTALL)
    return (match.group(1) if match else html).strip()


def _normalise_title(title: str) -> str:
    return re.sub(r"[^\w ]+", " ", title.lower()).strip()


def _tokens(text: str) -> set[str]:
    return {token for token in re.split(r"[\W_]+", text.lower()) if len(token) > 2}


def article_match(report_name: str, article: Article) -> float:
    """How surely the page is the article the report names, from 0 to 1.

    The page title is not enough: sites append their name ("Title | Site"),
    use a generic title ("Avis du CERT-FR") or rename a post after the feed
    published it. So the best of three signals counts: the page title, the
    share of the report name's words found at the top of the article text,
    and the words of the URL slug all found in the report name.
    """
    name = _normalise_title(report_name)
    if not name:
        return 0.0
    scores = []
    if article.title:
        title = _normalise_title(article.title)
        # A page title inside the report name counts only when it is a
        # title of its own, not a generic word ("Blog", "News").
        if title and (
            name in title or (title in name and len(_tokens(article.title)) >= 3)
        ):
            return 1.0
        scores.append(SequenceMatcher(None, name, title).ratio())
    name_tokens = _tokens(report_name)
    if name_tokens:
        head_tokens = _tokens(article.text[:1000])
        scores.append(len(name_tokens & head_tokens) / len(name_tokens))
    slug = urlparse(article.url).path.rstrip("/").rsplit("/", 1)[-1]
    slug_tokens = _tokens(slug)
    if len(slug_tokens) >= 3 and slug_tokens <= name_tokens:
        return 1.0
    return max(scores, default=0.0)


def judge(
    article: Article,
    report_name: str,
    current_content: str,
    min_length: int,
    length_ratio: float,
    min_title_similarity: float,
) -> Verdict:
    """Accept the article only if it is clearly the article.

    ``current_content`` is the text of the report's content today. When it
    is empty, nothing is replaced (the description is never touched), so the
    article only has to be the article. When it is filled, the article must
    also be longer than it by ``length_ratio``, so a full text is never
    replaced by less.
    """
    length = len(article.text)
    head = (article.title or "").lower() + " " + article.text[:2000].lower()
    blocked = next((marker for marker in _BLOCKED_MARKERS if marker in head), None)
    if blocked and length < 3000:
        return Verdict(False, f"blocked page ({blocked!r})")
    if length < min_length:
        return Verdict(False, f"too short ({length} characters)")
    if current_content and length < length_ratio * len(current_content):
        return Verdict(
            False,
            f"not longer than the report content ({length} vs {len(current_content)})",
        )
    match = article_match(report_name, article)
    if match < min_title_similarity:
        return Verdict(False, f"not the article ({article.title!r}, match {match:.2f})")
    return Verdict(True, f"{length} characters, match {match:.2f}")
