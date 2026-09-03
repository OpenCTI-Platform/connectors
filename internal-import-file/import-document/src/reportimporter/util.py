import configparser
import logging
import re
from typing import Dict, List

import ioc_finder
from dateparser.search import search_dates

logger = logging.getLogger(__name__)


class MyConfigParser(configparser.ConfigParser):
    """
    Credits for this class and the list functions go to Peter-Smit
    https://stackoverflow.com/a/11866695
    """

    def getlist(self, section: str, option: str) -> List[str]:
        value = self.get(section, option)
        return list(filter(None, (x.strip() for x in value.splitlines())))

    def getlistint(self, section: str, option: str) -> List[int]:
        return [int(x) for x in self.getlist(section, option)]

    def as_dict(self) -> Dict[str, str]:
        d = dict(self._sections)
        for k in d:
            d[k] = dict(self._defaults, **d[k])
            d[k].pop("__name__", None)
        return d


def library_mapping() -> Dict:
    return {
        "Autonomous-System.number": custom_asnparse,
        #        'Date.foo': custom_dateparse,
        "Domain-Name.value": ioc_finder.parse_domain_names,
        "Email-Addr.value": ioc_finder.parse_email_addresses,
        "IPv4-Addr.value": ioc_finder.parse_ipv4_addresses,
        "IPv6-Addr.value": ioc_finder.parse_ipv6_addresses,
        "Mac-Addr.value": custom_mac_addr_parse,
        "File.hashes.MD5": ioc_finder.parse_md5s,
        "File.hashes.SHA-1": ioc_finder.parse_sha1s,
        "File.hashes.SHA-256": ioc_finder.parse_sha256s,
        "Url.value": ioc_finder.parse_urls,
        "Vulnerability.name": ioc_finder.parse_cves,
        "Windows-Registry-Key.key": ioc_finder.parse_registry_key_paths,
    }


def custom_asnparse(text: str) -> List:
    values = ioc_finder.parse_asns(text)
    output = []
    for value in values:
        asn_value = re.findall(r"\d+", value)
        if asn_value:
            try:
                asn_value = int(asn_value[0])
                output.append(asn_value)
            except ValueError:
                logger.error(
                    "Could not convert ASN match to int", extra={"value": value}
                )
        else:
            logger.error("Could not extract ASN number", extra={"value": value})

    return output


def custom_dateparse(text: str) -> List:
    result = search_dates(text=text)
    if not result:
        return []
    else:
        return [value[1].isoformat(timespec="seconds") for value in result]


def custom_mac_addr_parse(text: str) -> List:
    mac_addresses = ioc_finder.parse_mac_addresses(text)
    return [x.lower() for x in mac_addresses]
