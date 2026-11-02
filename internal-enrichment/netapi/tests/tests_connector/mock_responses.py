"""Answers of the NetAPI JSON API as returned on 2026-10-26."""

import copy

LISTS_DOMAINS = {
    "page": "https://netapi.com/compromised-urls/",
    "current": "https://netapi.com/api2/?method=compromised&dataset_type=url",
    "all_time": "https://netapi.com/api2/?method=compromised&dataset_type=url-all",
}
SOURCE = "NetAPI compromised feed, updated daily (CC BY 4.0)"

# compromised-check: a domain listed now
CHECK_LISTED_NOW = {
    "value": "000359.xyz",
    "type": "domain",
    "listed_now": True,
    "listed_ever": True,
    "matched_value": "000359.xyz",
    "first_seen": "2023-02-25",
    "last_seen": "2026-10-26 01:05:27 UTC",
    "block_reason": "blackbook",
    "registrar": {
        "id": 1599,
        "name": "Alibaba Cloud Computing Ltd. d/b/a HiChina (www.net.cn)",
        "brand_name": "Alibaba Cloud",
        "page": "https://netapi.com/whois-alibaba-cloud-computing-ltd-d-b-a-hichina-www-net-cn/",
    },
    "note": "Seen in the compromised feed within the last 24 hours.",
    "lists": LISTS_DOMAINS,
    "source": SOURCE,
}

# compromised-check: a hostname matched through its registered domain
CHECK_LISTED_VIA_DOMAIN = {
    **copy.deepcopy(CHECK_LISTED_NOW),
    "value": "www.000359.xyz",
}

# compromised-check: a domain listed in the past only
CHECK_LISTED_PAST = {
    "value": "0-07.ru",
    "type": "domain",
    "listed_now": False,
    "listed_ever": True,
    "matched_value": "0-07.ru",
    "first_seen": "2019-12-18",
    "last_seen": "2019-12-25 00:00:00 UTC",
    "block_reason": "suspicious",
    "registrar": None,
    "note": (
        "Listed in the past but not seen in the last 24 hours; most such entries "
        "reflect past incidents only."
    ),
    "lists": LISTS_DOMAINS,
    "source": SOURCE,
}

# compromised-check: never listed
CHECK_CLEAN = {
    "value": "netapi.com",
    "type": "domain",
    "listed_now": False,
    "listed_ever": False,
    "matched_value": None,
    "first_seen": None,
    "last_seen": None,
    "block_reason": None,
    "registrar": None,
    "note": "Not in the current or historical compromised feed.",
    "lists": LISTS_DOMAINS,
    "source": SOURCE,
}

# domain-rank
RANK_IN_TOP_1M = {
    "domain": "github.com",
    "in_top_1m": True,
    "rank": 11,
    "snapshot_date": "2026-10-26",
    "tld": "com",
    "rank_in_tld": 11,
    "tld_sites_in_top_1m": 427432,
    "note": "Rank 1 = most popular. The list is rebuilt daily from SEO / link-graph and traffic signals.",
    "links": {
        "top_1m": "https://netapi.com/top-1-mln-websites/",
        "csv": "https://netapi.com/netapi_top1mln.csv",
    },
}
RANK_NOT_IN_TOP_1M = {
    "domain": "000359.xyz",
    "in_top_1m": False,
    "rank": None,
    "snapshot_date": "2026-10-26",
    "note": "Not in the current NetAPI Top 1M.",
    "links": RANK_IN_TOP_1M["links"],
}

# an API error
ERROR_INVALID_VALUE = {
    "error": {
        "code": "invalid_value",
        "message": "value must be a domain name or a hostname",
    }
}
