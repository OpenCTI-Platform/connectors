import ipaddress
from datetime import datetime

import pycti
import requests
import tldextract
import validators
import whois
from pydantic import TypeAdapter
from stix2 import ExternalReference


def threat_description_generator(group_name, group_data) -> str:
    """
    Retrieve description of a group name via https://api.ransomware.live/v2/groups response
    :param group_name: string
    :param group_data: json response (from https://api.ransomware.live/v2/groups)
    :return: description string
    """
    matching_items = [
        item for item in group_data if item.get("name", None) == group_name
    ]

    if matching_items[0].get("description") not in [None, "", " ", "null"]:
        description = matching_items[0].get("description", "No description available")
    else:
        description = "No description available"

    return description


def fetch_country_domain(domain: str):
    """
    Fetches the whois information of a domain
    :param domain:
    :return: string description of the domain with country, registrar, creation and expiration dates
    """
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

    return description


def ransom_note_generator(group_name: str):
    """
    Generates a ransom note external reference
    :param group_name:
    :return: ExternalReference object
    """
    if group_name in ("lockbit3", "lockbit2"):
        url = "https://www.ransomware.live/ransomnotes/lockbit"
    else:
        url = f"https://www.ransomware.live/ransomnotes/{group_name}"

    return ExternalReference(
        source_name="Ransom Note",
        url=url,
        description="Sample Ransom Note",
    )


def safe_datetime(value: str | None) -> datetime | None:
    """Safely parses a string into a naive datetime object (without timezone).
    Returns None if the input is None or not a valid ISO 8601 datetime string.
    Can avoid errors where fields are missing or incorrectly formed.
    :params value: The input string to validate and convert to datetime.
    :returns: datetime | None : A naive datetime object if the input is valid, otherwise None.
    :examples:
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
    :param domain:
    :return: IP of the given domain or None
    """
    params = {"name": domain, "type": "A"}

    headers = {"accept": "application/json", "User-Agent": "OpenCTI"}

    response = requests.get(
        "https://dns.google/resolve",
        headers=headers,
        params=params,
        timeout=(20000, 20000),
    )
    response.raise_for_status()

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
    :param value: Value in string
    :return: A boolean
    """
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def is_ipv6(value: str) -> bool:
    """
    Determine whether the provided IP string is IPv6
    :param value: Value in string
    :return: A boolean
    """
    try:
        ipaddress.IPv6Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def is_domain(value: str) -> bool:
    """
    Valid domain name regex including internationalized domain name
    :param value: Value in string
    :return: A boolean
    """
    return validators.domain(value)


def domain_extractor(url: str):
    """
    Extracts the domain from a URL
    :param url:
    :return: domain from url or None
    """
    if validators.domain(url):
        return url

    domain = tldextract.extract(url).top_domain_under_public_suffix
    if validators.domain(domain):
        return domain

    return None
