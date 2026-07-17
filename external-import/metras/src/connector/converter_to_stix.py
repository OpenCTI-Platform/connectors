"""STIX conversion for the Metras Feed (EXTERNAL_IMPORT).

Bulk converters: EDR alerts -> Incident (+ Attack-Pattern from mitre_ids, external Url,
and a System identity for the affected endpoint); binaries -> StixFile observables;
endpoints -> System identities. Internal asset IPs (agent_ip, interface IPs) are recorded
on the System identity description, NOT emitted as IPv4-Addr IOCs. Observables only — no
Indicators are auto-created (per build decision).
"""

from typing import TYPE_CHECKING

import stix2
from connector.utils import (
    is_mitre_attack_id,
    is_valid_hash,
    is_valid_url,
    severity_to_score,
    stix_timestamp,
)
from pycti import (
    AttackPattern,
    Identity,
    Incident,
    StixCoreRelationship,
)

if TYPE_CHECKING:
    from pycti import OpenCTIConnectorHelper

_TLP_BY_NAME = {
    "clear": stix2.TLP_WHITE,
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}


class ConverterToStix:
    """Factory for all STIX objects produced by the Feed connector."""

    def __init__(
        self, helper: "OpenCTIConnectorHelper", tlp_level: str = "amber"
    ) -> None:
        self.helper = helper
        self.tlp = _TLP_BY_NAME.get((tlp_level or "amber").lower(), stix2.TLP_AMBER)
        self.author = self._create_author()
        self._confidence = getattr(helper, "connect_confidence_level", None) or 50

    # ------------------------------------------------------------------ #
    # Author / common
    # ------------------------------------------------------------------ #
    @staticmethod
    def _create_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(name="Metras", identity_class="organization"),
            name="Metras",
            identity_class="organization",
            description="Metras endpoint detection & response (EDR) platform.",
            external_references=[
                stix2.ExternalReference(
                    source_name="Metras", url="https://dashboard.metras.sa/"
                )
            ],
        )

    def _marking_refs(self) -> list[str]:
        return [self.tlp["id"]]

    def create_relationship(
        self, source_id: str, rel_type: str, target_id: str, **kwargs
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            relationship_type=rel_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author["id"],
            object_marking_refs=self._marking_refs(),
            confidence=self._confidence,
            allow_custom=True,
            **kwargs,
        )

    # ------------------------------------------------------------------ #
    # Observables
    # ------------------------------------------------------------------ #
    def _custom_props(self, score: int | None = None) -> dict:
        props = {"x_opencti_created_by_ref": self.author["id"]}
        if score is not None:
            props["x_opencti_score"] = score
        return props

    def create_url(self, value: str, score: int | None = None) -> stix2.URL | None:
        if not is_valid_url(value):
            return None
        return stix2.URL(
            value=value,
            object_marking_refs=self._marking_refs(),
            custom_properties=self._custom_props(score),
        )

    def create_file(
        self,
        *,
        md5: str | None = None,
        sha1: str | None = None,
        sha256: str | None = None,
        name: str | None = None,
        size: int | None = None,
        score: int | None = None,
    ) -> stix2.File | None:
        # Only keep well-formed hashes — a malformed digest from the API would make
        # stix2.File raise and crash the whole import cycle.
        hashes = {
            algo: val
            for algo, val in (("MD5", md5), ("SHA-1", sha1), ("SHA-256", sha256))
            if is_valid_hash(algo, val)
        }
        if not hashes and not name:
            return None
        kwargs = {
            "object_marking_refs": self._marking_refs(),
            "custom_properties": self._custom_props(score),
        }
        if hashes:
            kwargs["hashes"] = hashes
        if name:
            kwargs["name"] = name
        if isinstance(size, int) and size >= 0:
            kwargs["size"] = size
        try:
            return stix2.File(**kwargs)
        except Exception:  # noqa: BLE001 - never let one bad record kill the cycle
            return None

    # ------------------------------------------------------------------ #
    # Domain objects
    # ------------------------------------------------------------------ #
    def create_attack_pattern(self, mitre_id: str) -> stix2.AttackPattern | None:
        if not is_mitre_attack_id(mitre_id):
            return None
        return stix2.AttackPattern(
            id=AttackPattern.generate_id(name=mitre_id, x_mitre_id=mitre_id),
            name=mitre_id,
            created_by_ref=self.author["id"],
            object_marking_refs=self._marking_refs(),
            custom_properties={"x_mitre_id": mitre_id},
            external_references=[
                stix2.ExternalReference(
                    source_name="mitre-attack",
                    external_id=mitre_id,
                    url=f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
                )
            ],
            allow_custom=True,
        )

    def create_system(
        self, name: str, *, description: str | None = None
    ) -> stix2.Identity | None:
        """A fleet endpoint/host modelled as a System identity (an internal asset,
        not an IOC). Internal asset IPs are kept in the description, not emitted as
        IPv4-Addr observables."""
        if not name:
            return None
        return stix2.Identity(
            id=Identity.generate_id(name=name, identity_class="system"),
            name=name,
            identity_class="system",
            description=description,
            created_by_ref=self.author["id"],
            object_marking_refs=self._marking_refs(),
            confidence=self._confidence,
            allow_custom=True,
        )

    def create_incident(
        self,
        *,
        name: str,
        description: str,
        severity: int | float | str | None,
        first_seen: str | None = None,
        last_seen: str | None = None,
        source: str | None = None,
        labels: list[str] | None = None,
        external_id: str | int | None = None,
    ) -> stix2.Incident:
        score, octi_sev = severity_to_score(severity)
        refs = []
        if external_id:
            refs.append(
                stix2.ExternalReference(
                    source_name="Metras", external_id=str(external_id)
                )
            )
        return stix2.Incident(
            id=Incident.generate_id(name=name, created=first_seen or stix_timestamp()),
            name=name,
            description=description,
            created_by_ref=self.author["id"],
            object_marking_refs=self._marking_refs(),
            labels=labels or [],
            first_seen=first_seen,
            last_seen=last_seen,
            confidence=self._confidence,
            external_references=refs or None,
            custom_properties={
                "x_opencti_score": score,
                "source": source or "Metras",
                "severity": octi_sev,
                "incident_type": "alert",
            },
            allow_custom=True,
        )

    # ------------------------------------------------------------------ #
    # High-level builders (record -> list[STIX])
    # ------------------------------------------------------------------ #
    def process_alert(self, alert: dict) -> list:
        """Convert one EDR alert into a connected STIX graph."""
        objects = []
        name = (
            alert.get("alert_name")
            or alert.get("alert_source_name")
            or "Metras EDR Alert"
        )
        endpoint_name = alert.get("endpoint_name")
        proc = alert.get("process") or {}
        proc_name = proc.get("name")
        proc_guid = proc.get("guid")

        first_seen = alert.get("last_occurrence_time")
        desc_lines = [
            f"Metras EDR alert: {name}",
            f"Type: {alert.get('type', 'n/a')}",
            f"Source: {alert.get('alert_source_name', 'n/a')}",
            f"Endpoint: {endpoint_name or 'n/a'} ({alert.get('endpoint_id', 'n/a')})",
            f"Occurrences: {alert.get('occurrence_count', 'n/a')}",
            f"Risk score: {alert.get('risk_score', 'n/a')}",
        ]
        if proc_name:
            desc_lines.append(f"Process: {proc_name} {proc_guid or ''}".strip())
        if alert.get("mitre_ids"):
            desc_lines.append(f"MITRE ATT&CK: {', '.join(alert['mitre_ids'])}")

        labels = []
        for lbl in alert.get("tags") or []:
            if lbl:
                labels.append(str(lbl))
        if alert.get("type"):
            labels.append(str(alert["type"]).lower())
        if alert.get("alert_source_name"):
            labels.append(str(alert["alert_source_name"]))

        incident = self.create_incident(
            name=name,
            description="\n".join(desc_lines),
            severity=alert.get("severity"),
            first_seen=first_seen,
            last_seen=first_seen,
            source="Endpoint",
            labels=labels,
            external_id=alert.get("id"),
        )
        objects.append(incident)

        # MITRE ATT&CK techniques -> Attack-Pattern (uses)
        for mid in alert.get("mitre_ids") or []:
            ap = self.create_attack_pattern(mid)
            if ap:
                objects.append(ap)
                objects.append(
                    self.create_relationship(incident["id"], "uses", ap["id"])
                )

        # url -> Url (external destination — a legitimate observable). agent_ip is the
        # affected host's INTERNAL IP and is recorded on the System identity, not as an IOC.
        url = alert.get("url")
        if url and is_valid_url(url):
            url_obj = self.create_url(url)
            if url_obj:
                objects.append(url_obj)
                objects.append(
                    self.create_relationship(
                        incident["id"], "related-to", url_obj["id"]
                    )
                )

        # endpoint -> System identity (internal asset, not infrastructure/IOC)
        if endpoint_name:
            agent_ip = alert.get("agent_ip")
            desc = "Metras EDR endpoint" + (
                f"; agent_ip={agent_ip}" if agent_ip else ""
            )
            system = self.create_system(endpoint_name, description=desc)
            if system:
                objects.append(system)
                objects.append(
                    self.create_relationship(incident["id"], "related-to", system["id"])
                )

        return objects

    def process_binary(self, binary: dict, malicious_only: bool = True) -> list:
        """Convert one binary into a StixFile observable (+ System identity link)."""
        runnability = (binary.get("runnability_status") or "").lower()
        signature = (binary.get("signature_status") or "").lower()
        is_malicious = runnability == "banned" or signature == "unsigned"
        if malicious_only and not is_malicious:
            return []

        score = (
            80 if runnability == "banned" else (60 if signature == "unsigned" else 30)
        )
        size = binary.get("file_size_bytes")
        sfile = self.create_file(
            md5=binary.get("md5"),
            sha1=binary.get("sha1"),
            sha256=binary.get("sha256"),
            name=binary.get("name"),
            size=size if isinstance(size, int) else None,
            score=score,
        )
        if not sfile:
            return []
        objects = [sfile]

        first_endpoint = binary.get("first_endpoint_name")
        if first_endpoint:
            system = self.create_system(
                first_endpoint, description="Metras EDR endpoint"
            )
            if system:
                objects.append(system)
                objects.append(
                    self.create_relationship(sfile["id"], "related-to", system["id"])
                )
        return objects

    def process_endpoint(self, endpoint: dict) -> list:
        """Convert one endpoint into a System identity (internal asset).

        Internal interface/tunnel IPs are recorded in the description, NOT emitted as
        IPv4-Addr observables (they are not IOCs).
        """
        name = endpoint.get("name") or endpoint.get("id")
        if not name:
            return []
        os_type = endpoint.get("os") or "unknown"

        ips = set()
        sc = endpoint.get("sc_connection_info") or {}
        if sc.get("tunnel_ip"):
            ips.add(sc["tunnel_ip"])
        nw = endpoint.get("nw_info") or {}
        for iface in (nw.get("interfaces") or []) if isinstance(nw, dict) else []:
            for ip_val in (iface.get("ips") or []) if isinstance(iface, dict) else []:
                ips.add(ip_val)

        ip_note = f"; ips={', '.join(sorted(ips))}" if ips else ""
        system = self.create_system(
            name,
            description=(
                f"Metras endpoint ({os_type}); "
                f"serial={endpoint.get('serial', 'n/a')}{ip_note}"
            ),
        )
        return [system] if system else []

    def author_object(self) -> stix2.Identity:
        return self.author
