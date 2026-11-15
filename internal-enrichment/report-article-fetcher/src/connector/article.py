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
from urllib.parse import urldefrag, urljoin, urlparse

import lxml.etree
import lxml.html
import requests
import trafilatura
from requests.adapters import HTTPAdapter
from trafilatura.htmlprocessing import convert_to_html
from trafilatura.utils import normalize_unicode
from trafilatura.xml import xmltotxt
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


def new_session(user_agent: str) -> requests.Session:
    """An HTTP session that only connects to public addresses.

    A worker keeps one session for all its reports, so the connections to a
    site stay open between articles (no new TCP and TLS handshake for each
    article of the same feed). A session is never shared between workers.
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
    return session


def fetch_html(
    url: str,
    user_agent: str,
    timeout: int,
    max_size: int,
    session: requests.Session | None = None,
) -> tuple[str, str]:
    """Download an HTML page over plain HTTP. Returns (final URL, HTML).

    Redirects are followed by hand so that every hop is checked. With a
    session, its open connections are reused; its cookies are cleared first,
    so that one site's cookies never reach the next article.
    """
    if session is None:
        session = new_session(user_agent)
    session.cookies.clear()
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

    The page is parsed and extracted once: the HTML body, the text and the
    title all come from the same extraction (trafilatura.extract would run
    the whole extraction again for each output format).
    """
    html = _prepare(html)
    document = trafilatura.bare_extraction(
        html,
        url=url,
        output_format="html",
        with_metadata=True,
        include_tables=True,
        include_formatting=True,
        include_links=True,
        # No images: their URLs would be fetched by whatever renders the
        # content later (the PDF export), outside the public-address checks.
        include_images=False,
        include_comments=False,
        favor_recall=True,
    )
    if document is None or document.body is None:
        return None
    # The text first: building the HTML output converts the body in place.
    text = normalize_unicode(xmltotxt(document.body, True))
    tree = convert_to_html(document.body)
    _drop_page_anchors(tree, url)
    _restore_code_elements(tree)
    # HTML serialisation, not XML: an empty element is written <a ...></a>,
    # never <a .../>, which an HTML parser reads as an unclosed tag.
    body = normalize_unicode(
        lxml.html.tostring(
            tree, method="html", pretty_print=True, encoding="unicode"
        ).strip()
    )
    if not body:
        return None
    return Article(url=url, title=document.title, html=_strip_document(body), text=text)


def _same_page(href: str, url: str) -> bool:
    """The link points at the page itself: empty, or a fragment of the page.

    A bare in-page link "#part" never reaches this point with its href:
    _prepare drops it, since trafilatura would rewrite it against the site
    root ("https://site#part"), where it could not be told apart from an
    explicit link to the root page, which is kept.
    """
    href = href.strip()
    if not href:
        return True
    target, fragment = urldefrag(href)
    if not fragment and not href.endswith("#"):
        return False
    if not target:
        return True
    page = urldefrag(url)[0]
    return target.rstrip("/") == page.rstrip("/")


def _restore_code_elements(tree: lxml.etree._Element) -> None:
    """Write a code block <pre><code>, as the page had it.

    trafilatura reads <pre><code> as one code element and writes it back
    as a <pre> inside a <pre>: the inner one becomes the <code> again.
    """
    for block in list(tree.iter("pre")):
        inner = block[0] if len(block) == 1 else None
        if (
            inner is not None
            and inner.tag == "pre"
            and not (block.text or "").strip()
            and not (inner.tail or "").strip()
        ):
            inner.tag = "code"


def _drop_page_anchors(tree: lxml.etree._Element, url: str) -> None:
    """Unwrap the links that lead nowhere, keeping their text and children.

    Headings often carry an in-page anchor (<a id="part"></a>, <a name>):
    trafilatura keeps it as a link with an empty href, which the report's
    content would render as a link reloading the page. Links to another
    page are kept: indicators often sit in them.
    """
    for link in list(tree.iter("a")):
        if _same_page(link.get("href") or "", url):
            _unwrap(link)


def _unwrap(element: lxml.etree._Element) -> None:
    """Replace the element with its content: text, children and tail."""
    parent = element.getparent()
    if parent is None:
        return
    children = list(element)
    leading = element.text or ""
    trailing = element.tail or ""
    if children:
        children[-1].tail = (children[-1].tail or "") + trailing
    else:
        leading += trailing
    previous = element.getprevious()
    if previous is not None:
        previous.tail = (previous.tail or "") + leading
    else:
        parent.text = (parent.text or "") + leading
    index = parent.index(element)
    parent[index : index + 1] = children


# One indicator alone in an element: a hash, an IPv4, a URL or a domain,
# defanged ("hxxp", "[.]", "[:]") or not.
_INDICATOR = re.compile(
    r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}"
    r"|(?:\d{1,3}(?:\.|\[\.\])){3}\d{1,3}"
    r"|h(?:tt|xx)ps?(?::|\[:\])//\S+"
    r"|(?:[\w-]+(?:\.|\[\.\]))+[a-z]{2,})$",
    re.IGNORECASE,
)


# Elements that hold one line of code each in a highlighter's markup (a
# <div> per line, a <pre> holding the whole text).
_LINE_BLOCKS = frozenset({"div", "p", "li", "pre"})


# Class or id words of the markup syntax highlighters and code viewers write
# around a line-numbered table (Crayon, Pygments, SyntaxHighlighter, Rouge,
# highlight.js, Prism, EnlighterJS, GitHub blobs).
_HIGHLIGHTER = re.compile(
    r"crayon|highlight|syntax|lineno|line-?num|gutter|blob-(?:num|code)"
    r"|hljs|prism|enlighter|rouge|sourcecode|code",
    re.IGNORECASE,
)


def _text_lines(element: lxml.etree._Element) -> list[str]:
    """The lines of an element's text, <br> read as a line break.

    The walk is iterative, so a deeply nested page cannot exhaust the
    interpreter's recursion limit.
    """
    parts: list[str] = []
    for event, node in lxml.etree.iterwalk(element, events=("start", "end")):
        if event == "start":
            if node.tag == "br":
                parts.append("\n")
            elif isinstance(node.tag, str) and node.text:
                parts.append(node.text)
        elif node is not element and node.tail:
            parts.append(node.tail)
    return "".join(parts).replace("\xa0", " ").split("\n")


def _code_lines(cell: lxml.etree._Element) -> list[str]:
    """The lines of code a highlighter's cell holds, indentation kept.

    Each innermost line element (one without line elements inside: a
    <div class="crayon-line">, a <div class="line">, a <pre>) gives its
    lines; a cell without one gives its own text, split on <br> and
    newlines. Trailing spaces and the final empty line of a <pre> are
    dropped.
    """
    blocks = [
        element for element in cell.iterdescendants() if element.tag in _LINE_BLOCKS
    ]
    # The elements holding a line element, found in one pass up from each
    # line element, so the cost stays linear in the size of the cell.
    holders: set[lxml.etree._Element] = set()
    for block in blocks:
        parent = block.getparent()
        while parent is not None and parent is not cell and parent not in holders:
            holders.add(parent)
            parent = parent.getparent()
    leaves = [block for block in blocks if block not in holders]
    lines: list[str] = []
    for leaf in leaves or [cell]:
        text = _text_lines(leaf)
        if leaf.tag == "pre" and len(text) > 1 and not text[-1].strip():
            text = text[:-1]
        lines.extend(line.rstrip() for line in text)
    if not leaves:
        while lines and not lines[0]:
            lines.pop(0)
        while lines and not lines[-1]:
            lines.pop()
    return lines


def _consecutive(numbers: list[str]) -> bool:
    """Line numbers: at least two, all digits, each one more than the last."""
    if len(numbers) < 2 or not all(number.isdigit() for number in numbers):
        return False
    first = int(numbers[0])
    return all(int(number) == first + i for i, number in enumerate(numbers))


def _row_cells(row: lxml.etree._Element) -> list[lxml.etree._Element]:
    return [cell for cell in row if cell.tag in ("td", "th")]


def _highlighter_markup(table: lxml.etree._Element) -> bool:
    """Whether the table carries a code marker: a highlighter class or id on
    the table, one of its rows or cells or one of its three nearest
    ancestors (the highlighter's wrappers), or a <pre> or <code> element
    inside it."""
    if table.xpath(".//pre | .//code"):
        return True
    ancestors = list(table.iterancestors())[:3]
    candidates = [table, *ancestors, *table.iter("tr", "td", "th")]
    return any(
        _HIGHLIGHTER.search(" ".join((node.get("class") or "", node.get("id") or "")))
        for node in candidates
    )


def _gutter_code(table: lxml.etree._Element) -> list[str] | None:
    """The code of a highlighter table with a line-number gutter, or None.

    Two layouts are recognised:
    - One row of two cells (Crayon, SyntaxHighlighter, Pygments and Rouge
      line numbers): the first cell holds only the numbers N..N+k, one per
      element or line, and the second cell holds exactly as many lines.
    - One row per line (GitHub, highlight.js line numbers): the first cell
      of each row carries its number in a data-line-number attribute (on
      itself or inside it) and holds no other text.
    Either layout must also carry a code marker (_highlighter_markup). Any
    other table, a data table whose first column counts the rows or an
    unmarked two-column table included, is not code and gives None.
    """
    if not _highlighter_markup(table):
        return None
    rows = [
        row for row in table.iter("tr") if row.xpath("ancestor::table[1]")[0] is table
    ]
    if len(rows) == 1:
        cells = _row_cells(rows[0])
        if len(cells) != 2:
            return None
        numbers = " ".join(_code_lines(cells[0])).split()
        code = _code_lines(cells[1])
        if _consecutive(numbers) and len(code) == len(numbers):
            return code
        return None
    numbers, code = [], []
    for row in rows:
        cells = _row_cells(row)
        if len(cells) != 2 or cells[0].text_content().strip():
            return None
        marked = cells[0].xpath("descendant-or-self::*[@data-line-number]")
        if not marked:
            return None
        numbers.append(marked[0].get("data-line-number").strip())
        code.append("\n".join(_code_lines(cells[1])))
    return code if _consecutive(numbers) else None


def _code_block(lines: list[str], tail: str | None) -> lxml.etree._Element:
    block = lxml.html.Element("pre")
    code = lxml.etree.SubElement(block, "code")
    code.text = "\n".join(lines)
    block.tail = tail
    return block


def _prepare(html: str) -> str:
    """Rework the layouts that make trafilatura drop indicators.

    - Code shown by a syntax highlighter with a line-number gutter (Crayon,
      SyntaxHighlighter, Pygments, GitHub...) is a <table>: trafilatura
      kept the numbers as a column of paragraphs and each line of code as
      a paragraph of its own, indentation lost. Each such table becomes a
      single <pre><code> block of its code lines.
    - Tables inside a chain of <div>s that only wrap them (Google Docs
      exports): trafilatura drops tables that deep, and the indicators of
      the Google Threat Intelligence posts were lost that way. Each table
      is lifted out of its wrappers.
    - Tables inside an "embed" block (Webflow's w-embed, Team Cymru):
      trafilatura discards any element whose class mentions "embed". The
      class is dropped from the ancestors of each table.
    - Indicators listed one per bare <div> (AhnLab ASEC): trafilatura takes
      the short blocks for page chrome. Such a run of <div>s becomes a list.
    - In-page links ("#part"): trafilatura rewrites them against the site
      root, so their href is dropped here, while it is still recognisable,
      and _drop_page_anchors unwraps them after the extraction.
    """
    try:
        document = lxml.html.fromstring(html)
    except (lxml.etree.ParserError, ValueError):
        return html
    changed = False
    for table in list(document.iter("table")):
        if table.getparent() is None or table.xpath("ancestor::table"):
            continue
        lines = _gutter_code(table)
        if lines is not None:
            table.getparent().replace(table, _code_block(lines, table.tail))
            changed = True
    for link in document.iter("a"):
        if (link.get("href") or "").strip().startswith("#"):
            del link.attrib["href"]
            changed = True
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
