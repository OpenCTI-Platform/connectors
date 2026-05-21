from typing import TYPE_CHECKING

from virustotal.processors.entity import EntityProcessor

if TYPE_CHECKING:
    from virustotal.builder import VirusTotalBuilder


class IPProcessor(EntityProcessor):
    """Enriches IPv4-Addr observables and Indicators."""

    def _fetch_data(self) -> dict:
        return self.client.get_ip_info(self.opencti_entity["observable_value"])

    def _enrich(self, builder: "VirusTotalBuilder", json_data: dict) -> None:
        if self.connector.ip_add_relationships:
            builder.create_asn_belongs_to()
            builder.create_location_located_at()

        if not self.is_indicator:
            builder.create_indicator_based_on(
                self.connector.ip_indicator_config,
                f"""[ipv4-addr:value = '{self.opencti_entity["observable_value"]}']""",
            )

        builder.create_notes()
