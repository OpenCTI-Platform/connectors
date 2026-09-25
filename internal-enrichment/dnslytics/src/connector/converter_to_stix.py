import ipaddress
from dataclasses import dataclass, field

from connector.hosting import Hosting
from connectors_sdk.models import (
    AutonomousSystem,
    DomainName,
    ExternalReference,
    IPV4Address,
    IPV6Address,
    OrganizationAuthor,
    Reference,
    Relationship,
    TLPMarking,
)
from dnslytics_client import DomainHit
from pycti import OpenCTIConnectorHelper

LABEL_ACTIVE = "dnslytics:active"
LABEL_DROPPED = "dnslytics:dropped"
PROVIDER_LABEL_PREFIX = "provider:"


@dataclass
class ConversionResult:
    stix_objects: list = field(default_factory=list)
    domains_created: int = 0
    # Active domains that resolve but miss `belongs-to` or `provider:` because a
    # lookup failed or the AS has no name: the enrichment fails
    incomplete: dict[str, str] = field(default_factory=dict)
    # Active domains on IPs not announced in global routing: no AS exists, so the
    # missing `belongs-to` / `provider:` is a warning, not a failure
    unannounced: dict[str, str] = field(default_factory=dict)


class ConverterToStix:
    """
    Converts DNSlytics hits and their hosting into STIX 2.1 objects,
    using the `connectors-sdk` models (deterministic ids for every object).
    """

    def __init__(self, helper: OpenCTIConnectorHelper, tlp_level: str):
        self.helper = helper
        self.tlp_marking = TLPMarking(level=tlp_level)
        self.author = OrganizationAuthor(
            name="DNSlytics",
            description="DNSlytics provides DNS, domain and hosting intelligence.",
            external_references=[
                ExternalReference(source_name="DNSlytics", url="https://dnslytics.com")
            ],
            markings=[self.tlp_marking],
        )

    def _common(self) -> dict:
        return {"author": self.author, "markings": [self.tlp_marking]}

    def _ip(self, value: str) -> IPV4Address | IPV6Address:
        if isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address):
            return IPV6Address(value=value, **self._common())
        return IPV4Address(value=value, **self._common())

    def _relationship(self, type_: str, source, target) -> Relationship:
        return Relationship(type=type_, source=source, target=target, **self._common())

    def convert(
        self,
        indicator_id: str,
        hits: list[DomainHit],
        hosting: Hosting | None,
    ) -> ConversionResult:
        """
        Build the objects for one run.
        `hosting` is None when `RESOLVE_HOSTING` is false: domains and active/dropped label only.
        """
        result = ConversionResult()
        indicator = Reference(id=indicator_id)
        models: list = [self.author, self.tlp_marking]
        ip_models: dict[str, IPV4Address | IPV6Address] = {}
        as_models: dict[int, AutonomousSystem] = {}
        belongs_to_done: set[tuple[str, int]] = set()

        for hit in hits:
            labels = [LABEL_ACTIVE if hit.active else LABEL_DROPPED]
            ips = (
                hosting.ips_by_domain.get(hit.domain, [])
                if hosting and hit.active
                else []
            )

            providers: list[str] = []
            failed: list[str] = []
            unannounced: list[str] = []
            nameless_as = False
            for ip in ips:
                as_info = hosting.as_by_ip.get(ip)
                if ip in hosting.ip2asn_errors:
                    failed.append(ip)
                elif as_info is None:
                    unannounced.append(ip)
                elif not as_info.name:
                    nameless_as = True
                elif as_info.name not in providers:
                    providers.append(as_info.name)
            labels += [PROVIDER_LABEL_PREFIX + provider for provider in providers]

            domain = DomainName(
                value=hit.domain,
                labels=labels,
                external_references=[
                    ExternalReference(
                        source_name="DNSlytics",
                        url=f"https://search.dnslytics.com/domain/{hit.domain}",
                    )
                ],
                **self._common(),
            )
            # OpenCTI only allows `based-on` from an Indicator to an Observable
            models += [domain, self._relationship("based-on", indicator, domain)]
            result.domains_created += 1

            for ip in ips:
                if ip not in ip_models:
                    ip_models[ip] = self._ip(ip)
                    models.append(ip_models[ip])
                models.append(self._relationship("resolves-to", domain, ip_models[ip]))

                as_info = hosting.as_by_ip.get(ip)
                if as_info is None:
                    continue
                if as_info.number not in as_models:
                    as_models[as_info.number] = AutonomousSystem(
                        number=as_info.number, name=as_info.name, **self._common()
                    )
                    models.append(as_models[as_info.number])
                if (ip, as_info.number) not in belongs_to_done:
                    belongs_to_done.add((ip, as_info.number))
                    models.append(
                        self._relationship(
                            "belongs-to", ip_models[ip], as_models[as_info.number]
                        )
                    )

            errors = []
            if failed:
                errors.append(f"IP2ASN failed for {', '.join(failed)}")
            if nameless_as and not providers:
                errors.append("AS has no name, no provider label")
            if errors:
                result.incomplete[hit.domain] = "; ".join(errors)
            if unannounced:
                result.unannounced[hit.domain] = (
                    f"not announced, no AS for {', '.join(unannounced)}"
                )

        result.stix_objects = [model.to_stix2_object() for model in models]
        return result
