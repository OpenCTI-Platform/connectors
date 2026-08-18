"""Test fixtures for the CISA ICS Advisories connector.

Adds `src/` to sys.path so tests can `import main` without packaging the
connector, mirroring how it is invoked at runtime (`python3 main.py` from
`src/`).
"""

import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def sample_advisory():
    """The RSS-derived advisory record for the fixture below."""
    return {
        "id": "ICSA-26-225-05",
        "title": "ANDRITZ HIPASE-250 and 250 SCALA",
        "link": "https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-05",
        "pub_date": "Thu, 13 Aug 26 12:00:00 +0000",
        "csaf_url": (
            "https://raw.githubusercontent.com/cisagov/CSAF/develop/"
            "csaf_files/OT/white/2026/icsa-26-225-05.json"
        ),
    }


@pytest.fixture
def sample_csaf():
    """A real CISA ICS Advisory CSAF document, fetched from
    cisagov/CSAF (csaf_files/OT/white/2026/icsa-26-225-05.json) for use as a
    fixed test fixture. Multi-vulnerability, multi-product, so it exercises
    de-duplication of CVEs and vendor/product identities across records."""
    return json.loads((FIXTURES / "icsa-26-225-05.json").read_text())


@pytest.fixture
def rss_item_xml():
    """A single RSS <item> in the exact shape CISA's ICS Advisories feed
    emits, including the CSAF link buried in <description>."""
    return """
    <item>
      <title>ANDRITZ HIPASE-250 and 250 SCALA</title>
      <link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-05</link>
      <description>&lt;p&gt;&lt;a href="https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-225-05.json"&gt;&lt;strong&gt;View CSAF&lt;/strong&gt;&lt;/a&gt;&lt;/p&gt;
      &lt;h2&gt;Summary&lt;/h2&gt;</description>
      <pubDate>Thu, 13 Aug 26 12:00:00 +0000</pubDate>
      <creator>CISA</creator>
      <guid>/node/25294</guid>
    </item>
    """
