from typing import Any

from censys_enrichment.converters.base import CensysConverter, ObservableLike
from censys_enrichment.converters.host import HostConverter
from censys_platform import Certificate, Host
from connectors_sdk.models import Reference, Relationship
from connectors_sdk.models.enums import RelationshipType


class DomainConverter(CensysConverter):
    def _fetch_data(self, observable: ObservableLike) -> dict[str, list[Any]]:
        client = self._require_client()
        return {
            "hosts": list(client.fetch_hosts(observable["value"])),
            "certs": list(client.fetch_certs_by_domain(observable["value"])),
        }

    def _convert(self, observable: ObservableLike, data: dict[str, list[Any]]) -> None:
        self._append_hosts(stix_entity=observable, hosts=data["hosts"])
        self._append_domain_certs(stix_entity=observable, certs=data["certs"])

    def _append_hosts(self, stix_entity: ObservableLike, hosts: list[Host]) -> None:
        host_converter = HostConverter()
        host_converter.builder = self.builder

        for host in hosts:
            ip_stix = self.builder.add_ip(
                observable=Reference(id=stix_entity.get("id")),
                ip=host.ip,
            )
            host_converter._convert(observable=ip_stix.to_stix2_object(), data=host)

    def _append_domain_certs(
        self, stix_entity: ObservableLike, certs: list[Certificate]
    ) -> None:
        """Append certificate STIX objects and domain relationships to the bundle.

        Args:
            stix_entity: The domain STIX entity
            certs: List of Certificate objects from Censys

        Side effects:
            Appends STIX objects (and a related-to relationship per certificate) to
            self.builder.bundle.
        """
        observable = Reference(id=stix_entity.get("id"))

        self.builder.add_author_and_marking()

        for cert in certs:
            certificate = self.builder.add_certificate(cert=cert)
            if certificate:
                self.builder.bundle.append(
                    Relationship(
                        source=certificate,
                        target=observable,
                        type=RelationshipType.RELATED_TO,
                        **self.builder.common_props,
                    )
                )
