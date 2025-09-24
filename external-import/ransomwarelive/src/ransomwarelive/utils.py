import ipaddress
from datetime import datetime

import requests
import tldextract
import validators
import whois
from pydantic import TypeAdapter


def threat_description_generator(group_name: str, group_data) -> str:
    """
    Retrieve description of a group name

    Params:
        group_name: group name in string
        group_data: data json response
    Return:
        description in string
    """
    matching_items = [
        item for item in group_data if item.get("name", None) == group_name
    ]

    if matching_items and matching_items[0].get("description") not in [
        None,
        "",
        " ",
        "null",
    ]:
        description = matching_items[0].get("description", "No description available")
    else:
        description = "No description available"

    return description


def fetch_country_domain(domain: str):
    """
    Fetches the whois information of a domain

    Param:
        domain: domain in string
    Return:
        string description of the domain with country, registrar, creation and expiration dates
    """
    try:
        w = whois.whois(domain)

        description = f"Domain:{domain}  \n"
        if w.get("country") is not None:
            description += f" is registered in {w.get('country')}  \n"
        if w.get("registrar") is not None:
            description += f"registered with {w.get('registrar')}  \n"
        if w.get("creation_date") is not None:
            description += f" creation_date {w.get('creation_date')}  \n"
        if w.get("expiration_date") is not None:
            description += f" expiration_date {w.get('expiration_date')}  \n"
    except whois.parser.PywhoisError:
        description = None
    return description


def safe_datetime(value: str | None) -> datetime | None:
    """Safely parses a string into a naive datetime object (without timezone).
    Returns None if the input is None or not a valid ISO 8601 datetime string.
    Can avoid errors where fields are missing or incorrectly formed.

    Param:
        value: The input string to validate and convert to datetime.
    Return:
        datetime | None : A naive datetime object if the input is valid, otherwise None.
    Examples:
        self.safe_datetime("2025-01-01 07:20:50.000000", "attack_date")
        > datetime.datetime(2025, 1, 1, 7, 20, 50, 0)

        self.safe_datetime(None, "attack_date")
        > None

        self.safe_datetime("invalid-date", "attack_date")
        > None
    """
    return TypeAdapter(datetime).validate_python(value)


def ip_fetcher(domain: str):
    """
    Fetches the IP address of a domain
    (Maybe possibility to improve with ipaddress.ip_address(item.get("data")).version)

    Param:
        domain: domain in string
    Return:
        IP of the given domain or None
    """
    params = {"name": domain, "type": "A"}

    headers = {"accept": "application/json", "User-Agent": "OpenCTI"}

    response = requests.get(
        "https://dns.google/resolve",
        headers=headers,
        params=params,
        timeout=(20000, 20000),
    )
    # response.raise_for_status()
    # Google DNS does not take into account characters with accents.
    # In this case, a status_code = 400 is raise and stop all the process.
    # In a first step, we disable raise_for_status
    # Then we will search to another management instead of dns google

    if response.status_code == 200:
        response_json = response.json()
        if response_json.get("Answer") is not None:
            for item in response_json.get("Answer"):
                if item.get("type") == 1 and is_ipv4(item.get("data")):
                    ip_address = item.get("data")
                    return ip_address
    return None


def is_ipv4(value: str) -> bool:
    """
    Determine whether the provided IP string is IPv4

    Param:
        value: ip value in string
    Return:
        A boolean
    """
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def is_ipv6(value: str) -> bool:
    """
    Determine whether the provided IP string is IPv6

    Param:
        value: ip value in string
    Return:
        A boolean
    """
    try:
        ipaddress.IPv6Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def is_domain(value: str) -> bool:
    """
    Valid domain name regex including internationalized domain name

    Param:
        value: domain in string
    Return:
        A boolean
    """
    return validators.domain(value)


def domain_extractor(url: str):
    """
    Extracts the domain from a URL

    Param:
        url: url in string
    Return:
        domain from url or None
    """
    if validators.domain(url):
        return url

    domain = tldextract.extract(url).top_domain_under_public_suffix
    if validators.domain(domain):
        return domain

    return None
