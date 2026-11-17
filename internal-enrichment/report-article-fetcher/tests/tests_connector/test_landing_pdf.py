"""A landing page that links its report as a PDF on the same site."""

import base64
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector import connector as connector_module
from connector.article import (
    Article,
    FetchError,
    extract_article,
    fetch_pdf,
    find_report_pdf,
    pdf_name,
    pdf_to_html,
)
from connector.connector import STIX_EXT_OCTI, ReportArticleFetcherConnector
from pdf_builder import build_pdf
from test_article_fixtures import PAGES as LONG_PAGES
from test_fetch import (  # noqa: F401 pylint: disable=unused-import
    ROUTES,
    checked,
    server,
)

FIXTURES = Path(__file__).parent / "fixtures"
CERTFR = "https://www.cert.cyber.gouv.fr/cti/CERTFR-2026-CTI-010/"
CERTFR_PDF = "https://www.cert.cyber.gouv.fr/uploads/CERTFR-2026-CTI-010.pdf"
NAME = "Point de situation de l’opération REACTIV – octobre 2026"

HEADER = "CERT-FR TLP:CLEAR"
FOOTER = "Point de situation REACTIV"
REPORT_PAGES = [
    [
        HEADER,
        "Synthèse",
        "Depuis le début de l'opération, les attaquants exploitent la",
        "vulnérabilité CVE-2026-12345 dans les passerelles VPN et dé-",
        "ploient le maître d'œuvre ShadowReactiv sur les serveurs exposés.",
        "",
        "Les adresses 198.51.100.7 et 203.0.113.9 sont observées.",
        FOOTER,
        "1",
    ],
    [
        HEADER,
        "Recommandations",
        "Appliquer les correctifs de l'éditeur et surveiller les connexions",
        "sortantes vers les infrastructures listées en annexe du rapport.",
        FOOTER,
        "2",
    ],
    [
        HEADER,
        "Annexe : indicateurs de compromission listés par le CERT-FR.",
        FOOTER,
        "3",
    ],
]
PDF = build_pdf(REPORT_PAGES)


def _landing() -> Article:
    html = (FIXTURES / "certfr-landing.html").read_text(encoding="utf-8")
    article = extract_article(CERTFR, html)
    assert article is not None
    return article


def test_the_report_pdf_of_the_landing_page_is_found_and_footer_pdfs_are_not():
    article = _landing()
    # The page also links RFC2350 in its menu and its terms of use in its
    # footer: the extraction drops both, only the report is left.
    assert find_report_pdf(article, CERTFR) == CERTFR_PDF


def test_a_pdf_on_another_site_is_not_followed():
    article = Article(
        url=CERTFR,
        title=NAME,
        html='<p><a href="https://cdn.other.example/report.pdf">Download the'
        " report</a></p>",
        text="x",
    )
    assert find_report_pdf(article, CERTFR) is None


def test_a_pdf_on_a_sub_domain_of_the_same_site_is_followed():
    article = Article(
        url=CERTFR,
        title=NAME,
        html='<p><a href="https://cyber.gouv.fr/r.pdf">Rapport</a></p>',
        text="x",
    )
    assert find_report_pdf(article, CERTFR) == "https://cyber.gouv.fr/r.pdf"


def test_the_link_that_says_report_wins_over_an_earlier_pdf():
    article = Article(
        url=CERTFR,
        title=NAME,
        html='<p><a href="/annex.pdf">Annexe</a></p>'
        '<p><a href="/uploads/full.pdf#page=2">Télécharger le rapport</a></p>',
        text="x",
    )
    assert find_report_pdf(article, CERTFR) == (
        "https://www.cert.cyber.gouv.fr/uploads/full.pdf"
    )


def test_the_text_of_the_pdf_is_paragraphs_without_running_headers():
    html, text = pdf_to_html(PDF)
    assert HEADER not in text and FOOTER not in text
    assert "<p>Synthèse</p>" in html
    assert "<p>Recommandations</p>" in html
    # Lines of one paragraph are joined, a word cut by a hyphen too.
    assert "la vulnérabilité CVE-2026-12345 dans les passerelles VPN et" in text
    assert "et déploient le maître" in text
    assert "Les adresses 198.51.100.7 et 203.0.113.9 sont observées." in text
    # Page numbers are dropped.
    assert "\n1\n" not in f"\n{text}\n"


def test_a_broken_or_empty_pdf_is_a_value_error():
    with pytest.raises(ValueError, match="cannot read the PDF"):
        pdf_to_html(b"%PDF-1.4 not a document")
    with pytest.raises(ValueError, match="no text"):
        pdf_to_html(build_pdf([[]]))


def test_the_name_of_the_attached_file_is_the_one_of_the_url():
    assert pdf_name(CERTFR_PDF) == "CERTFR-2026-CTI-010.pdf"
    assert pdf_name("https://x.example/a%20b.pdf?x=1") == "a b.pdf"


# fetch_pdf against the local server of test_fetch


def test_fetch_pdf_accepts_a_pdf_only(server, checked, monkeypatch):  # noqa: F811
    monkeypatch.setitem(
        ROUTES, "/report.pdf", (200, {"Content-Type": "application/pdf"}, PDF)
    )
    monkeypatch.setitem(
        ROUTES,
        "/fake.pdf",
        (200, {"Content-Type": "application/pdf"}, b"<html>login</html>"),
    )
    final_url, data = fetch_pdf(
        f"{server}/report.pdf", user_agent="t", timeout=5, max_size=100_000
    )
    assert (final_url, data) == (f"{server}/report.pdf", PDF)
    with pytest.raises(FetchError, match="Not a PDF: text/html"):
        fetch_pdf(f"{server}/page", user_agent="t", timeout=5, max_size=100_000)
    with pytest.raises(FetchError, match="does not start with %PDF"):
        fetch_pdf(f"{server}/fake.pdf", user_agent="t", timeout=5, max_size=100_000)
    with pytest.raises(FetchError, match="PDF larger than 100 bytes"):
        fetch_pdf(f"{server}/report.pdf", user_agent="t", timeout=5, max_size=100)
    # Every hop is checked as for a page.
    assert checked[0] == f"{server}/report.pdf"


# Through the connector


def _connector(**overrides):
    helper = MagicMock()
    helper.check_max_tlp.return_value = True
    helper.stix2_create_bundle.side_effect = lambda objects: {"objects": objects}
    settings = dict(
        user_agent="test",
        request_timeout=5,
        max_download_size=5_000_000,
        min_length=500,
        length_ratio=1.5,
        min_title_similarity=0.6,
        match_single_reference=False,
        max_workers=1,
        summary_log_level="error",
        follow_pdf=True,
        landing_max_length=4000,
        max_pdf_size=20_000_000,
    )
    settings.update(overrides)
    config = SimpleNamespace(
        connector=SimpleNamespace(max_tlp="amber"),
        report_article_fetcher=SimpleNamespace(**settings),
    )
    return ReportArticleFetcherConnector(config=config, helper=helper), helper


REPORT = {
    "id": "report--3b4f6a7e-6d7c-4a7c-9a1f-0e1f2a3b4c5d",
    "type": "report",
    "name": NAME,
    "external_references": [
        {
            "source_name": NAME,
            "description": f"CERT-FR {NAME}. Retrieved 2026-11-16T10:00:00.000Z.",
            "url": CERTFR,
        }
    ],
}


@pytest.fixture
def landing(monkeypatch):
    """The CERT-FR page is served; the PDF fetch is recorded and answered."""
    html = (FIXTURES / "certfr-landing.html").read_text(encoding="utf-8")
    monkeypatch.setattr(connector_module, "fetch_html", lambda url, **_: (url, html))
    fetched = []

    def fetch_pdf(url, **kwargs):
        fetched.append((url, kwargs["max_size"]))
        return url, PDF

    monkeypatch.setattr(connector_module, "fetch_pdf", fetch_pdf)
    return fetched


def test_a_landing_page_gets_the_text_and_the_file_of_its_report(landing):
    connector, _ = _connector()
    enriched, message = connector._enrich(REPORT)

    assert landing == [(CERTFR_PDF, 20_000_000)]
    content = enriched["extensions"][STIX_EXT_OCTI]["content"]
    # The landing page first, then the report.
    assert content.index("REACTIV") < content.index("<p>Synthèse</p>")
    assert "ShadowReactiv" in content
    (attached,) = enriched["x_opencti_files"]
    assert attached["name"] == "CERTFR-2026-CTI-010.pdf"
    assert attached["mime_type"] == "application/pdf"
    assert base64.b64decode(attached["data"]) == PDF
    assert message.startswith("Article and its PDF report CERTFR-2026-CTI-010.pdf")


def test_the_report_pdf_is_not_followed_when_turned_off(landing):
    connector, _ = _connector(follow_pdf=False)
    enriched, _ = connector._enrich(REPORT)
    assert landing == []
    assert "x_opencti_files" not in enriched


def test_a_long_page_is_not_a_landing_page(landing):
    connector, _ = _connector(landing_max_length=1000)
    enriched, _ = connector._enrich(REPORT)
    assert landing == []
    assert "x_opencti_files" not in enriched


@pytest.mark.parametrize(
    "error",
    [
        FetchError("PDF larger than 20000000 bytes"),
        FetchError("Not a PDF: text/html"),
        ValueError("no text in the PDF"),
    ],
)
def test_a_failed_pdf_keeps_the_landing_page_alone(landing, monkeypatch, error):
    def fail(*_, **__):
        raise error

    monkeypatch.setattr(connector_module, "fetch_pdf", fail)
    connector, helper = _connector()
    enriched, message = connector._enrich(REPORT)

    assert message.startswith("Article written to the report")
    assert "x_opencti_files" not in enriched
    assert "REACTIV" in enriched["extensions"][STIX_EXT_OCTI]["content"]
    helper.connector_logger.warning.assert_called_once()
    assert helper.connector_logger.warning.call_args.kwargs["meta"]["reason"] == (
        str(error)
    )


def test_an_unreadable_pdf_keeps_the_landing_page_alone(landing, monkeypatch):
    monkeypatch.setattr(
        connector_module, "fetch_pdf", lambda url, **_: (url, b"%PDF-1.4 broken")
    )
    connector, helper = _connector()
    enriched, _ = connector._enrich(REPORT)
    assert "x_opencti_files" not in enriched
    helper.connector_logger.warning.assert_called_once()


@pytest.mark.parametrize("name", list(LONG_PAGES))
def test_real_articles_never_follow_a_pdf(name):
    html = (FIXTURES / f"{name}.html").read_text(encoding="utf-8")
    article = extract_article(LONG_PAGES[name], html)
    # Above the landing threshold the PDF step does not even look for a link;
    # a short news article (bleepingcomputer) links no report PDF of its own.
    assert (
        len(article.text) >= 4000 or find_report_pdf(article, LONG_PAGES[name]) is None
    )
