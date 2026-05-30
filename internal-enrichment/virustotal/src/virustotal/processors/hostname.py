from typing import TYPE_CHECKING

from virustotal.processors.entity import EntityProcessor

if TYPE_CHECKING:
    from virustotal.builder import VirusTotalBuilder


class HostnameProcessor(EntityProcessor):
    """Enriches Domain-Name and Hostname observables and Indicators."""

    def _fetch_data(self) -> dict:
        return self.client.get_domain_info(self.opencti_entity["observable_value"])

    def _enrich(self, builder: "VirusTotalBuilder", json_data: dict) -> None:
        if self.connector.domain_add_relationships:
            for ip in [
                r["value"]
                for r in json_data["data"]["attributes"].get("last_dns_records", [])
                if r["type"] == "A"
            ]:
                self.helper.log_debug(
                    f"[VirusTotal] adding ip {ip} to domain"
                    f" {self.opencti_entity['observable_value']}"
                )
                builder.create_ip_resolves_to(ip)

        if not self.is_indicator:
            builder.create_indicator_based_on(
                self.connector.domain_indicator_config,
                f"""[domain-name:value = '{self.opencti_entity["observable_value"]}']""",
            )

        builder.create_notes()
