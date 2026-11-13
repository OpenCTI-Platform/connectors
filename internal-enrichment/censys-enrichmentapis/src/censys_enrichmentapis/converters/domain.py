from typing import Any

from censys_enrichmentapis.converters.base import CensysConverter, ObservableLike
from censys_platform import Certificate, Webproperty
from connectors_sdk.models import Reference


class DomainConverter(CensysConverter):
    def _fetch_data(self, observable: ObservableLike) -> dict[str, list[Any]]:
        client = self._require_client()
        return {
            "web_properties": list(
                client.fetch_web_properties(observable["value"], ports=(80, 443))
            ),
            "certs": list(client.fetch_certs_by_domain(observable["value"])),
        }

    def _convert(self, observable: ObservableLike, data: dict[str, list[Any]]) -> None:
        self.primary_observable_labels = self._format_censys_labels(
            (
                self._value(threat, "name")
                for web_property in data["web_properties"]
                for threat in self._value(web_property, "threats") or []
            ),
            category="Threat",
        )
        self.builder.add_author_and_marking()
        self._append_web_properties(
            stix_entity=observable,
            web_properties=data["web_properties"],
        )
        self._append_domain_certs(stix_entity=observable, certs=data["certs"])

    def _append_web_properties(
        self,
        stix_entity: ObservableLike,
        web_properties: list[Webproperty],
    ) -> None:
        observable = Reference(id=stix_entity.get("id"))
        for web_property in web_properties:
            threat_labels = self._format_censys_labels(
                (
                    self._value(threat, "name")
                    for threat in self._value(web_property, "threats") or []
                ),
                category="Threat",
            )
            self.builder.services.add_web_property_note(
                observable=observable,
                web_property=web_property,
                labels=threat_labels,
            )

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

        for cert in certs:
            self.builder.certificates.add_certificate(
                cert=cert,
                related_observable=observable,
            )
