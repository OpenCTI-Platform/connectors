import ipaddress
import re
from abc import ABC
from urllib.parse import quote, urlparse

import validators
from tldextract import tldextract


class IoCParser(ABC):
    """
    An utility class to help parsing any IoC,
    useful for extracting IP or domain from URL

    :param ioc: the IoC to be parsed, any string actually
    """

    __SAFE_CHARS = ":/?!=#&$+@"
    type = "unknown"
    valid = False
    tld_extracted = None
    url_parsed = None
    url_type = "unknown"
    ip_parsed = None

    def __init__(self, ioc: str) -> None:
        self._IOC = ioc
        extractor = tldextract.TLDExtract()
        self.tld_extracted = extractor(self._IOC, include_psl_private_domains=True)
        self.url_parsed = urlparse(self._IOC)
        try:
            self.ip_parsed = ipaddress.ip_address(self._IOC)
        except ValueError:
            self.ip_parsed = ipaddress.ip_address("0.0.0.0")
        self.validate()
        self.sanitize()

    def sanitize(self) -> str:
        self._IOC = quote(self._IOC, safe=self.__SAFE_CHARS)
        return self._IOC

    def validate(self) -> bool:
        self.valid = bool(validators.url(self._IOC))
        if self.valid:
            if validators.domain(self.url_parsed.hostname):
                self.url_type = "domain"
            if validators.ipv4(self.url_parsed.hostname):
                self.url_type = "ipv4"
            if validators.ipv6(self.url_parsed.hostname):
                self.url_type = "ipv6"
        self.type = "url"
        if not self.valid:
            self.valid = bool(validators.domain(self._IOC))
            self.type = "domain"
        if not self.valid:
            self.valid = bool(validators.ipv4(self._IOC))
            self.type = "ipv4"
        if not self.valid:
            self.valid = bool(validators.ipv6(self._IOC))
            self.type = "ipv6"
        if not self.valid:
            if self.is_hash():
                self.valid = True
                self.type = "hash"
        if not self.valid:
            self.type = "unknown"
        return self.valid

    def is_hash(self) -> bool:
        return self.is_md5() or self.is_64_hash()

    def is_md5(self) -> bool:
        return re.fullmatch(r"([a-fA-F\d]{32})", self._IOC) is not None

    def is_64_hash(self) -> bool:
        is_number_only = re.match(r"[0-9]", self._IOC)
        try:
            bits = bin(int(self._IOC))
        except ValueError:
            return False
        return len(bits) >= 60 and is_number_only is not None

    def get_result(self) -> str or bool:
        """
        Tries to extract the IP or domain from the IoC

        :return: the extracted IP or domain, otherwise False
        """
        if not self.valid:
            return ""
        return (
            (str(self.ip_parsed) if str(self.ip_parsed) != "0.0.0.0" else False)
            or self.tld_extracted.fqdn
            or self.tld_extracted.ipv4
            or self.tld_extracted.domain
            or ""
        )

    def get_tld_extracted(self) -> dict:
        if not self.valid:
            return {}
        return {
            "fqdn": self.tld_extracted.fqdn,
            "domain": self.tld_extracted.domain,
            "subdomain": self.tld_extracted.subdomain,
            "registered_domain": self.tld_extracted.registered_domain,
            "suffix": self.tld_extracted.suffix,
            # @NOTE: relies on https://publicsuffix.org/list/
            "is_private_tld": self.tld_extracted.is_private,
        }

    def get_url_parsed(self) -> dict:
        if not self.valid:
            return {}
        return {
            "scheme": self.url_parsed.scheme,
            "hostname": self.url_parsed.hostname,
            "port": self.url_parsed.port,
            "path": self.url_parsed.path,
            "query": self.url_parsed.query,
            "params": self.url_parsed.params,
            "username": self.url_parsed.username,
            "password": self.url_parsed.password,
            "fragment": self.url_parsed.fragment,
            "netloc": self.url_parsed.netloc,
            "url_type": self.url_type,
        }

    def get_ip_parsed(self) -> dict:
        if not self.valid:
            return {}
        return (
            {
                "is_global": self.ip_parsed.is_global,
                "is_link_local": self.ip_parsed.is_link_local,
                "is_loopback": self.ip_parsed.is_loopback,
                "is_multicast": self.ip_parsed.is_multicast,
                "is_private_ip": self.ip_parsed.is_private,
                "is_reserved": self.ip_parsed.is_reserved,
                "is_unspecified": self.ip_parsed.is_unspecified,
                "ip_version": self.ip_parsed.version,
            }
            if self.type in ["ipv4", "ipv6"]
            else {}
        )

    def summary(self) -> dict:
        """
        All the extracted data from the IoC, including some useful metadata

        :return: dict
        """
        if not self.valid:
            return {}
        return {
            "valid": self.valid,
            "result": self.get_result(),
            "type": self.type,
            "sanitized": self._IOC,
            "metadata": {
                **self.get_tld_extracted(),
                **self.get_url_parsed(),
                **self.get_ip_parsed(),
                "is_md5": self.is_md5(),
                "is_64_hash": self.is_64_hash(),
            },
        }
