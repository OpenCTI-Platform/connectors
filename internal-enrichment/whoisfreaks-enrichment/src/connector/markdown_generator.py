"""
WhoisFreaks OpenCTI Connector — Markdown Generator
===================================================

Produces an analyst-readable markdown note shown in the OpenCTI UI when a
Domain-Name observable is enriched. Sections:

1. Summary table (registration, registrar, dates)
2. Name servers
3. Domain status (EPP codes)
4. Registrant / contact details (when not redacted)

Every WHOIS-derived value is Markdown-escaped before it reaches the note: the
values come from the domain owner, so an unescaped `[click](https://attacker)`
in a contact or registrar field would otherwise render as a live link inside a
trusted report. The per-request query time is intentionally left out of the
note so re-enriching an unchanged domain produces the same deterministic note
id instead of a duplicate.
"""

from __future__ import annotations

from whoisfreaks_client.models import WhoisRecord

_FOOTER = "---\n*Enriched by the WhoisFreaks OpenCTI Connector*"

# Characters that would let a WHOIS value inject links, images, emphasis, code,
# inline HTML or extra table cells into the note.
_MD_ESCAPE = str.maketrans({c: "\\" + c for c in "\\`*_[]()<>|!"})


def _esc(value) -> str:
    """Escape Markdown so attacker-controlled WHOIS values render as plain text."""
    return str(value).translate(_MD_ESCAPE)


class MarkdownGenerator:
    """Stateless generator: call ``generate`` with a WHOIS record."""

    def generate(self, record: WhoisRecord) -> str:
        sections = [
            self._summary_table(record),
            self._name_servers(record),
            self._domain_status(record),
            self._contacts(record),
            _FOOTER,
        ]
        return "\n\n".join(s for s in sections if s)

    # ------------------------------------------------------------------ #

    def _summary_table(self, record: WhoisRecord) -> str:
        reg = record.registrar
        rows = [
            (
                "Domain",
                f"`{_esc(record.domain_name)}`" if record.domain_name else "N/A",
            ),
            ("Registered", _esc(record.domain_registered) or "N/A"),
            ("Registrar", _esc(reg.name) or "N/A"),
            ("Registrar IANA ID", _esc(reg.iana_id) or "N/A"),
            ("Registrar URL", _esc(reg.website_url) or "N/A"),
            ("Creation date", _esc(record.create_date) or "N/A"),
            ("Updated date", _esc(record.update_date) or "N/A"),
            ("Expiry date", _esc(record.expiry_date) or "N/A"),
            ("DNSSEC", "Yes" if record.secure_dns else "No"),
            ("WHOIS server", _esc(record.whois_server) or "N/A"),
        ]
        lines = ["## WHOIS Summary", "", "| Field | Value |", "| :--- | :--- |"]
        lines += [f"| {label} | {value} |" for label, value in rows]
        return "\n".join(lines)

    def _name_servers(self, record: WhoisRecord) -> str:
        if not record.name_servers:
            return ""
        lines = ["## Name Servers", ""]
        lines += [f"- `{_esc(ns)}`" for ns in record.name_servers]
        return "\n".join(lines)

    def _domain_status(self, record: WhoisRecord) -> str:
        if not record.domain_status:
            return ""
        lines = ["## Domain Status", ""]
        lines += [f"- {_esc(status)}" for status in record.domain_status]
        return "\n".join(lines)

    def _contacts(self, record: WhoisRecord) -> str:
        blocks = [
            ("Registrant", self._contact_lines(record.registrant)),
            ("Administrative", self._contact_lines(record.administrative)),
            ("Technical", self._contact_lines(record.technical)),
            ("Billing", self._contact_lines(record.billing)),
        ]
        rendered = [
            f"**{label} contact**\n\n" + "\n".join(lines)
            for label, lines in blocks
            if lines
        ]
        abuse = self._abuse_lines(record)
        if abuse:
            rendered.append("**Abuse contact**\n\n" + "\n".join(abuse))
        if not rendered:
            return ""
        return "## Contacts\n\n" + "\n\n".join(rendered)

    @staticmethod
    def _contact_lines(contact) -> list[str]:
        fields = [
            ("Name", contact.name),
            ("Organization", contact.company),
            ("Email", contact.email_address),
            ("Phone", contact.phone),
            ("Street", contact.street),
            ("City", contact.city),
            ("State", contact.state),
            ("Postal code", contact.zip_code),
            ("Country", contact.country_name or contact.country_code),
        ]
        return [f"- **{label}:** {_esc(value)}" for label, value in fields if value]

    @staticmethod
    def _abuse_lines(record: WhoisRecord) -> list[str]:
        fields = [
            ("Email", record.abuse.email_address),
            ("Phone", record.abuse.phone_number),
        ]
        return [f"- **{label}:** {_esc(value)}" for label, value in fields if value]
