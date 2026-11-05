"""Convert WhoisFreaks WHOIS records into STIX 2.1 objects for OpenCTI."""

from connector.markdown_generator import MarkdownGenerator
from connectors_sdk.models import (
    DomainName,
    EmailAddress,
    ExternalReference,
    Note,
    Organization,
    OrganizationAuthor,
    Reference,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import TLPLevel
from pycti import STIX_EXT_OCTI_SCO, OpenCTIStix2
from whoisfreaks_client import WhoisRecord

SOURCE_NAME = "WhoisFreaks"

# Phrases registrars return in place of a withheld contact. Kept as multi-word or
# distinctive strings (not bare "privacy"/"gdpr") so a real value such as
# `privacy@example.com` or `gdpr@example.com` is not mistaken for a placeholder.
_REDACTION_MARKERS = (
    "redacted",
    "redacted for privacy",
    "redacted for gdpr",
    "data protected",
    "data redacted",
    "not disclosed",
    "non-public data",
    "statutory masking",
    "gdpr masked",
    "privacy protect",
    "whois privacy",
    "withheld for privacy",
    "please query",
)


class ConverterToStix:
    """Build the STIX objects for one WHOIS enrichment.

    New entities come from `connectors_sdk.models`, which gives every object the
    deterministic ID OpenCTI expects, so enriching the same domain again updates the
    same entities. The enriched observable itself is updated in place (labels, external
    reference), so it keeps its own markings and author.
    """

    def __init__(self, tlp_level: TLPLevel):
        self.author = OrganizationAuthor(
            name=SOURCE_NAME,
            description="Domain and WHOIS data provider.",
            external_references=[
                ExternalReference(
                    source_name=SOURCE_NAME, url="https://whoisfreaks.com"
                )
            ],
        )
        self.marking = TLPMarking(level=tlp_level)
        self.markdown = MarkdownGenerator()

    def _relationship(self, rel_type: str, source, target, description: str):
        return Relationship(
            type=rel_type,
            source=source,
            target=target,
            description=description,
            author=self.author,
            markings=[self.marking],
        )

    def build(
        self,
        record: WhoisRecord,
        stix_entity: dict,
        *,
        create_labels: bool = True,
        create_relationships: bool = True,
        create_note: bool = True,
    ) -> list:
        """Return the new STIX objects; `stix_entity` is updated in place."""
        observable = Reference(id=stix_entity["id"])
        entities: list = [self.author, self.marking]
        relationships: list = []

        def link(rel_type, source, target, description):
            if create_relationships:
                relationships.append(
                    self._relationship(rel_type, source, target, description)
                )

        # --- Registrar -------------------------------------------------------
        if record.registrar.name:
            registrar = Organization(
                name=record.registrar.name,
                description=self._registrar_description(record),
                contact_information=self._registrar_contact(record) or None,
                author=self.author,
                markings=[self.marking],
            )
            entities.append(registrar)
            link(
                "related-to",
                observable,
                registrar,
                "Domain registered through this registrar",
            )

        # --- Registrant organization ----------------------------------------
        if _usable(record.registrant.company):
            registrant_org = Organization(
                name=record.registrant.company.strip(),
                description="Registrant organization (WHOIS)",
                author=self.author,
                markings=[self.marking],
            )
            if registrant_org.id not in {e.id for e in entities}:
                entities.append(registrant_org)
            link(
                "related-to",
                observable,
                registrant_org,
                "Registrant organization of the domain",
            )

        # --- Name servers ----------------------------------------------------
        for ns in self._name_servers(record):
            nameserver = DomainName(
                value=ns, author=self.author, markings=[self.marking]
            )
            if nameserver.id not in {e.id for e in entities}:
                entities.append(nameserver)
                link("related-to", observable, nameserver, "Name server of the domain")

        # --- Contact e-mail addresses ---------------------------------------
        for email, roles in self._contact_emails(record).items():
            email_obj = EmailAddress(
                value=email, author=self.author, markings=[self.marking]
            )
            if email_obj.id not in {e.id for e in entities}:
                entities.append(email_obj)
            link("related-to", observable, email_obj, ", ".join(roles))

        # --- Note ------------------------------------------------------------
        if create_note:
            entities.append(
                Note(
                    abstract=f"WhoisFreaks WHOIS record for {record.domain_name or stix_entity['value']}",
                    content=self.markdown.generate(record),
                    objects=[observable],
                    author=self.author,
                    markings=[self.marking],
                )
            )

        labels = self._labels(record) if create_labels else []
        self._update_observable(stix_entity, record, labels)
        return [obj.to_stix2_object() for obj in entities + relationships]

    # ------------------------------------------------------------------ #
    # Field extraction
    # ------------------------------------------------------------------ #

    @staticmethod
    def _registrar_description(record: WhoisRecord) -> str | None:
        reg = record.registrar
        details = [
            f"{label}: {value}"
            for label, value in (
                ("IANA ID", reg.iana_id),
                ("Website", reg.website_url),
                ("WHOIS server", reg.whois_server),
                ("Status", reg.status),
            )
            if value
        ]
        return ", ".join(details) or None

    @staticmethod
    def _registrar_contact(record: WhoisRecord) -> str:
        reg = record.registrar
        parts = [p for p in (reg.email_address, reg.phone_number) if p]
        return " / ".join(parts)

    @staticmethod
    def _name_servers(record: WhoisRecord) -> list[str]:
        """Clean, de-duplicated, lower-cased name server hostnames."""
        seen: list[str] = []
        for ns in record.name_servers:
            value = ns.strip().rstrip(".").lower()
            if "." in value and " " not in value and value not in seen:
                seen.append(value)
        return seen

    def _contact_emails(self, record: WhoisRecord) -> dict[str, list[str]]:
        """Map each unique contact e-mail to the role(s) it plays."""
        candidates = (
            (record.registrant.email_address, "Registrant email"),
            (record.administrative.email_address, "Administrative contact email"),
            (record.technical.email_address, "Technical contact email"),
            (record.billing.email_address, "Billing contact email"),
            (record.abuse.email_address, "Abuse contact email"),
        )
        emails: dict[str, list[str]] = {}
        for raw, role in candidates:
            value = raw.strip()
            if not _is_email(value):
                continue
            emails.setdefault(value.lower(), [])
            if role not in emails[value.lower()]:
                emails[value.lower()].append(role)
        return emails

    @staticmethod
    def _labels(record: WhoisRecord) -> list[str]:
        labels: list[str] = []
        if not record.is_registered:
            labels.append("unregistered")
        if record.secure_dns:
            labels.append("dnssec")
        return labels

    # ------------------------------------------------------------------ #
    # Observable update
    # ------------------------------------------------------------------ #

    @staticmethod
    def _lookup_reference(domain: str) -> ExternalReference:
        return ExternalReference(
            source_name=SOURCE_NAME,
            url=f"https://whoisfreaks.com/tools/whois?domain={domain}",
            description=f"WhoisFreaks WHOIS lookup of {domain}",
        )

    def _update_observable(self, stix_entity, record, labels) -> None:
        for label in labels:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "labels", label, True
            )
        reference = self._lookup_reference(record.domain_name or stix_entity["value"])
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity,
            STIX_EXT_OCTI_SCO,
            "external_references",
            {
                "source_name": reference.source_name,
                "url": reference.url,
                "description": reference.description,
            },
            True,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _usable(value: str) -> bool:
    """True when a WHOIS string is present and not a redaction placeholder."""
    value = (value or "").strip()
    if not value:
        return False
    lowered = value.lower()
    return not any(marker in lowered for marker in _REDACTION_MARKERS)


def _is_email(value: str) -> bool:
    """Loose check that a WHOIS contact value is a real, non-redacted e-mail."""
    if not _usable(value):
        return False
    if value.count("@") != 1:
        return False
    local, _, domain = value.partition("@")
    return bool(local) and "." in domain and " " not in value
