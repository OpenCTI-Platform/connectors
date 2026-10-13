import ipaddress
from datetime import datetime, timezone

import stix2
from connector.settings import SpurConfig
from pycti import (
    Identity,
    Indicator,
    Location,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


class ConverterToStix:  # pylint: disable=too-few-public-methods
    def __init__(self, helper: OpenCTIConnectorHelper, config: SpurConfig):
        self.helper = helper
        self.default_score = config.default_score
        self.create_indicators = config.create_indicators
        self.create_asns = config.create_asns
        self.create_locations = config.create_locations

        self.author = self._create_author()
        self.tlp_marking = self._create_tlp_marking(config.tlp_level.lower())

    @staticmethod
    def _create_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(name="Spur", identity_class="organization"),
            name="Spur",
            identity_class="organization",
            description="Spur provides anonymous infrastructure intelligence, identifying VPNs, proxies, and residential exit nodes.",
            external_references=[
                stix2.ExternalReference(
                    source_name="Spur",
                    url="https://spur.us",
                    description="Spur threat intelligence platform.",
                )
            ],
        )

    @staticmethod
    def _create_tlp_marking(level: str):
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[level]

    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking],
        )

    def convert_ip_context(self, record: dict) -> list:
        """Convert one Spur IP Context record into a list of STIX 2.1 objects."""
        ip = record.get("ip", "")
        if not ip:
            return []

        objects = []

        score = self._compute_score(record)
        labels = self._compute_labels(record)
        description = self._build_description(record)

        # Primary observable
        obs = self._create_ip_observable(ip, score, labels, description)
        if obs is None:
            return []
        objects.append(obs)

        # AutonomousSystem
        if self.create_asns and record.get("as"):
            asn_obj, asn_rel = self._create_asn(record["as"], obs.id)
            objects.extend([asn_obj, asn_rel])

        # Location
        if self.create_locations and record.get("location"):
            loc_obj, loc_rel = self._create_location(record["location"], obs.id)
            if loc_obj:
                objects.extend([loc_obj, loc_rel])

        # Indicator (only for IPs with risks or tunnel data)
        if self.create_indicators and (record.get("risks") or record.get("tunnels")):
            ind_obj, ind_rel = self._create_indicator(ip, obs.id, record)
            objects.extend([ind_obj, ind_rel])

        return objects

    def _compute_score(self, record: dict) -> int:
        risks = record.get("risks", [])
        return min(100, self.default_score + len(risks) * 5)

    def _compute_labels(self, record: dict) -> list[str]:
        labels = list(record.get("risks", []))

        infra = record.get("infrastructure")
        if infra:
            labels.append(infra)

        for tunnel in record.get("tunnels", []):
            t_type = tunnel.get("type")
            if t_type and t_type not in labels:
                labels.append(t_type)
            operator = tunnel.get("operator")
            if operator and operator not in labels:
                labels.append(operator)

        return [lbl.lower().replace("_", "-") for lbl in labels if lbl]

    def _build_description(self, record: dict) -> str:
        parts = []

        as_info = record.get("as", {})
        if as_info:
            parts.append(
                f"**AS**: AS{as_info.get('number', '?')} {as_info.get('organization', '')}"
            )

        org = record.get("organization")
        if org:
            parts.append(f"**Organization**: {org}")

        loc = record.get("location", {})
        if loc:
            parts.append(
                f"**Location**: {loc.get('city', '')}, {loc.get('state', '')}, {loc.get('country', '')}"
            )

        infra = record.get("infrastructure")
        if infra:
            parts.append(f"**Infrastructure**: {infra}")

        services = record.get("services", [])
        if services:
            parts.append(f"**Services**: {', '.join(services)}")

        risks = record.get("risks", [])
        if risks:
            parts.append(f"**Risks**: {', '.join(risks)}")

        tunnels = record.get("tunnels", [])
        if tunnels:
            tunnel_strs = [
                f"{t.get('operator', 'unknown')} ({t.get('type', '?')})"
                for t in tunnels
            ]
            parts.append(f"**Tunnels**: {', '.join(tunnel_strs)}")

        client = record.get("client", {})
        if client:
            c_types = ", ".join(client.get("types", []))
            c_count = client.get("count", 0)
            c_countries = client.get("countries", 0)
            if c_types or c_count:
                parts.append(
                    f"**Clients**: {c_types} — {c_count} clients across {c_countries} countries"
                )

        ai = record.get("ai")
        if ai:
            ai_types = ", ".join(ai.get("types", []))
            parts.append(f"**AI activity**: {ai.get('operator', '')} ({ai_types})")

        return "\n\n".join(parts)

    def _create_ip_observable(
        self, ip: str, score: int, labels: list[str], description: str
    ):
        custom = {
            "x_opencti_score": score,
            "x_opencti_description": description,
            "x_opencti_labels": labels,
            "x_opencti_created_by_ref": self.author.id,
        }
        try:
            if self._is_ipv6(ip):
                return stix2.IPv6Address(
                    value=ip,
                    object_marking_refs=[self.tlp_marking],
                    custom_properties=custom,
                )
            if self._is_ipv4(ip):
                return stix2.IPv4Address(
                    value=ip,
                    object_marking_refs=[self.tlp_marking],
                    custom_properties=custom,
                )
            self.helper.connector_logger.warning(
                "[SPUR] Unrecognised IP value — skipping", meta={"ip": ip}
            )
            return None
        except Exception as err:
            self.helper.connector_logger.error(
                "[SPUR] Failed to create IP observable",
                meta={"ip": ip, "error": str(err)},
            )
            return None

    def _create_asn(
        self, as_info: dict, obs_id: str
    ) -> tuple[stix2.AutonomousSystem, stix2.Relationship]:
        number = as_info.get("number", 0)
        name = as_info.get("organization", f"AS{number}")
        asn = stix2.AutonomousSystem(
            number=number,
            name=name,
            object_marking_refs=[self.tlp_marking],
            custom_properties={"x_opencti_created_by_ref": self.author.id},
        )
        rel = self.create_relationship(obs_id, "belongs-to", asn.id)
        return asn, rel

    def _create_location(self, loc_info: dict, obs_id: str) -> tuple:
        city = loc_info.get("city", "")
        country = loc_info.get("country", "")
        if not city and not country:
            return None, None

        loc_name = city if city else country
        loc = stix2.Location(
            id=Location.generate_id(loc_name, "City" if city else "Country"),
            name=loc_name,
            country=country if country else None,
            city=city if city else None,
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "x_opencti_location_type": "City" if city else "Country",
                "x_opencti_created_by_ref": self.author.id,
            },
        )
        rel = self.create_relationship(obs_id, "located-at", loc.id)
        return loc, rel

    def _create_indicator(
        self, ip: str, obs_id: str, record: dict
    ) -> tuple[stix2.Indicator, stix2.Relationship]:
        addr_type = "ipv6-addr" if self._is_ipv6(ip) else "ipv4-addr"
        pattern = f"[{addr_type}:value = '{ip}']"
        risks = record.get("risks", [])
        ind = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            name=f"Spur: {ip}",
            description=f"Spur flagged this IP. Risks: {', '.join(risks) if risks else 'none'}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.now(tz=timezone.utc),
            created_by_ref=self.author.id,
            labels=["malicious-activity"] if risks else ["anomalous-activity"],
            object_marking_refs=[self.tlp_marking],
        )
        rel = self.create_relationship(ind.id, "based-on", obs_id)
        return ind, rel

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False
