from .enricher import Enricher
from .ioc_parser import IoCParser
from .url_domain_enricher import URLDomainEnricher
from .url_ipv4_enricher import URLIPv4Enricher
from .url_ipv6_enricher import URLIPv6Enricher


class URLEnricher(Enricher):
    """
    The URL Enrichment class
    """

    _ioc_parser: dict = dict()

    def enrich(self) -> list:
        """
        Enriches a URL by extracting the IP or Domain from it

        :return: the enriched objects
        """

        match self._ioc_parser.url_type:
            case "ipv4":
                return URLIPv4Enricher(
                    self._helper, self._stix_entity, self._ioc_parser.get_result()
                ).process()
            case "ipv6":
                return URLIPv6Enricher(
                    self._helper, self._stix_entity, self._ioc_parser.get_result()
                ).process()
            case "domain":
                return URLDomainEnricher(
                    self._helper, self._stix_entity, self._ioc_parser.get_result()
                ).process()
            case _:
                raise ValueError(
                    f"{self._ioc_parser.url_type} is not a supported entity type."
                )

    def process(self) -> list:
        self._ioc_parser = IoCParser(self._stix_entity.get("value"))
        self._helper.log_debug(f"ioc_parser type: {self._ioc_parser.url_type}")
        return self.enrich()
