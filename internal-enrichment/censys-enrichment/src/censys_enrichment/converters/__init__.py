from censys_enrichment.converters.base import CensysConverter
from censys_enrichment.converters.certificate import CertificateConverter
from censys_enrichment.converters.domain import DomainConverter
from censys_enrichment.converters.host import HostConverter
from censys_enrichment.errors import EntityTypeNotSupportedError

_CONVERTER_MAP: dict[str, type[CensysConverter]] = {
    "IPv4-Addr": HostConverter,
    "IPv6-Addr": HostConverter,
    "X509-Certificate": CertificateConverter,
    "Domain-Name": DomainConverter,
    "ipv4-addr": HostConverter,
    "ipv6-addr": HostConverter,
    "x509-certificate": CertificateConverter,
    "domain-name": DomainConverter,
}


def get_converter(entity_type: str) -> CensysConverter:
    cls = _CONVERTER_MAP.get(entity_type)
    if cls is None:
        raise EntityTypeNotSupportedError(
            f"Observable type {entity_type} not supported"
        )
    return cls()


__all__ = [
    "CensysConverter",
    "CertificateConverter",
    "DomainConverter",
    "HostConverter",
    "get_converter",
]
