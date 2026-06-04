import ipaddress
import re
import uuid

import stix2
from connector.utils import normalize_timestamp
from pycti import (
    Identity,
    Indicator,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


class ConverterToStix:
    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self.author = stix2.Identity(
            id=Identity.generate_id(
                name="CyberBlindSpot", identity_class="organization"
            ),
            name="CyberBlindSpot",
            identity_class="organization",
            description="CTM360 Digital Risk Protection platform",
        )
        # Populated during incidents_to_stix() for CaseIncident creation
        self.incident_case_metadata = []

    def _ext_ref(self, source_name: str, external_id: str, url: str = None):
        ref = {"source_name": source_name, "external_id": str(external_id)}
        if url:
            ref["url"] = url
        return stix2.ExternalReference(**ref)

    def _severity_to_score(self, severity: str) -> int:
        mapping = {
            "critical": 95,
            "high": 80,
            "medium": 55,
            "low": 30,
            "info": 10,
            "informational": 10,
        }
        return mapping.get(str(severity).lower(), 50)

    def _severity_to_priority(self, severity: str) -> str:
        mapping = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
        return mapping.get(str(severity).lower(), "P3")

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to OpenCTI-valid values (low, medium, high, critical)."""
        s = str(severity).lower()
        if s in ("critical", "high", "medium", "low"):
            return s
        if s in ("info", "informational"):
            return "low"
        return "medium"

    def _slugify_label(self, text: str) -> str:
        """Convert a label to lowercase kebab-case."""
        return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")

    @staticmethod
    def _escape_stix_value(value: str) -> str:
        """Escape backslashes and single quotes for safe STIX string literals."""
        return str(value).replace("\\", "\\\\").replace("'", "\\'")

    @staticmethod
    def _stable_fallback_id(prefix: str, *fields) -> str:
        """Build a deterministic identifier from stable content fields.

        Used when a CBS record has no ``id`` so repeated imports of the same
        record reuse the same external reference / STIX seed instead of minting
        a fresh ``uuid4`` (and therefore duplicate Notes/Indicators) on every
        run. Falls back to the prefix alone when no content field is present.
        """
        seed = "|".join(str(f) for f in fields if f)
        return f"cbs-{prefix}-{uuid.uuid5(uuid.NAMESPACE_URL, seed or prefix)}"

    def incidents_to_stix(self, incidents: list) -> list:
        self.incident_case_metadata = []
        objects = [self.author]
        for inc in incidents:
            inc_id = inc.get("id", "")
            subject = inc.get("subject", "Unknown incident")
            severity = inc.get("severity", "medium")
            # Treat a missing/blank/whitespace-only type as "Unknown" so the
            # slugified label is never empty — an empty label would later trigger
            # an add_label(label_name="") call during CaseIncident creation.
            inc_type = str(inc.get("type") or "").strip() or "Unknown"
            status = inc.get("status", "unknown")
            coa = inc.get("coa", "")
            source = inc.get("source", "")
            remarks = inc.get("remarks", "")
            brand = inc.get("brand", "")
            created = normalize_timestamp(inc.get("created_date"))

            if not inc_id:
                self.helper.connector_logger.warning(
                    "[CONVERTER] Skipping incident with no id",
                    meta={"subject": subject},
                )
                continue

            # Build description with markdown formatting
            desc_lines = [
                f"**Type:** {inc_type}",
                f"**Subject:** {subject}",
                f"**Status:** {status}",
                f"**Severity:** {severity}",
            ]
            if coa and coa != "None":
                desc_lines.append(f"**Course of Action:** {coa}")
            if source:
                desc_lines.append(f"**Source:** {source}")
            if brand:
                desc_lines.append(f"**Brand:** {brand}")
            if remarks:
                desc_lines.append(f"**Remarks:** {remarks}")
            description = "\n\n".join(desc_lines)

            type_label = self._slugify_label(inc_type)

            # Build case name: remarks - subject [id]
            case_name = (
                f"{remarks} - {subject} [{inc_id}]"
                if remarks
                else f"{subject} [{inc_id}]"
            )

            # Collect labels (no severity). Only include the type label when
            # slugification yields a non-empty value (a type made up solely of
            # punctuation slugifies to "") so no empty label is ever emitted.
            case_labels = ["ctm360-cbs"]
            if type_label:
                case_labels.insert(0, type_label)
            if status and status.lower() != "unknown":
                case_labels.append(f"status:{status.lower()}")
            if coa and coa.lower() not in ("none", ""):
                case_labels.append(f"coa:{self._slugify_label(coa)}")
            if brand:
                case_labels.append(f"Brand:{brand}")
            if source:
                case_labels.append(f"Source:{source}")

            self.incident_case_metadata.append(
                {
                    "ticket_id": str(inc_id),
                    "name": case_name,
                    "description": description,
                    "severity": self._normalize_severity(severity),
                    "priority": self._severity_to_priority(severity),
                    "response_types": [inc_type] if inc_type else [],
                    "labels": case_labels,
                    "created": created,
                    # Normalised current status, used to seed the status tracker
                    # so the first poll cycle does not treat it as a change.
                    "status": str(status).lower(),
                }
            )

        return objects

    def malware_logs_to_stix(self, logs: list) -> list:
        objects = [self.author]
        # De-duplicate Malware SDOs per family within a single conversion run.
        # The Malware id is derived from the family, so emitting one object per
        # log would put several "malware" objects sharing the same id (but with
        # differing external_references / auto-generated timestamps) in the same
        # bundle, causing conflicting updates on ingestion.
        malware_by_family = {}
        for log in logs:
            malware_family = log.get("malware_family", "Unknown")
            domain = log.get("domain", "")
            ip_val = log.get("ip", "")
            email = log.get("email", "")

            malware_obj = None
            if malware_family and malware_family != "Unknown":
                malware_obj = malware_by_family.get(malware_family)
                if malware_obj is None:
                    # Family-stable external reference so the shared Malware
                    # object stays byte-identical across every log of the same
                    # family and across runs (no per-record id on a family SDO).
                    ext_ref = self._ext_ref(
                        "CTM360-CyberBlindSpot", f"malware:{malware_family}"
                    )
                    malware_obj = stix2.Malware(
                        id=Malware.generate_id(malware_family),
                        name=malware_family,
                        is_family=True,
                        description="Malware family detected by CTM360 CyberBlindSpot",
                        created_by_ref=self.author.id,
                        external_references=[ext_ref],
                        custom_properties={"x_opencti_score": 80},
                    )
                    malware_by_family[malware_family] = malware_obj
                    objects.append(malware_obj)

            if ip_val:
                try:
                    ipaddress.ip_address(ip_val)
                    ip_obs = stix2.IPv4Address(
                        value=ip_val,
                        custom_properties={
                            "x_opencti_score": 70,
                            "x_opencti_created_by_ref": self.author.id,
                        },
                    )
                    objects.append(ip_obs)
                    if malware_obj is not None:
                        objects.append(
                            stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "uses", malware_obj.id, ip_obs.id
                                ),
                                relationship_type="uses",
                                source_ref=malware_obj.id,
                                target_ref=ip_obs.id,
                                created_by_ref=self.author.id,
                            )
                        )
                except ValueError:
                    pass

            if domain:
                domain_obs = stix2.DomainName(
                    value=domain,
                    custom_properties={
                        "x_opencti_score": 60,
                        "x_opencti_created_by_ref": self.author.id,
                    },
                )
                objects.append(domain_obs)
                if malware_obj is not None:
                    objects.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "uses", malware_obj.id, domain_obs.id
                            ),
                            relationship_type="uses",
                            source_ref=malware_obj.id,
                            target_ref=domain_obs.id,
                            created_by_ref=self.author.id,
                        )
                    )

            if email and "@" in email:
                email_obs = stix2.EmailAddress(
                    value=email,
                    custom_properties={
                        "x_opencti_score": 60,
                        "x_opencti_created_by_ref": self.author.id,
                    },
                )
                objects.append(email_obs)
                if malware_obj is not None:
                    objects.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "uses", malware_obj.id, email_obs.id
                            ),
                            relationship_type="uses",
                            source_ref=malware_obj.id,
                            target_ref=email_obs.id,
                            created_by_ref=self.author.id,
                        )
                    )

        return objects

    def breached_credentials_to_stix(self, creds: list) -> list:
        objects = [self.author]
        for cred in creds:
            email = cred.get("email", "")
            username = cred.get("username", "")
            domain = cred.get("domain", "")
            breach_source = cred.get("breach_source", "Unknown")
            created = normalize_timestamp(cred.get("date"))
            # A missing id must not become a random uuid4: it seeds the Note and
            # Indicator ids, so a fresh value each run would duplicate them.
            cred_id = cred.get("id") or self._stable_fallback_id(
                "breach", email, username, domain, breach_source
            )

            ext_ref = self._ext_ref("CTM360-CyberBlindSpot", cred_id)

            object_refs = [self.author.id]

            if email and "@" in email:
                email_obs = stix2.EmailAddress(
                    value=email,
                    custom_properties={
                        "x_opencti_score": 75,
                        "x_opencti_created_by_ref": self.author.id,
                    },
                )
                objects.append(email_obs)
                object_refs.append(email_obs.id)

            if domain:
                domain_obs = stix2.DomainName(
                    value=domain,
                    custom_properties={
                        "x_opencti_score": 50,
                        "x_opencti_created_by_ref": self.author.id,
                    },
                )
                objects.append(domain_obs)
                object_refs.append(domain_obs.id)

            user_display = username or email or "unknown"
            user_account = stix2.UserAccount(
                user_id=user_display,
                account_login=username or email,
                display_name=user_display,
                custom_properties={
                    "x_opencti_score": 75,
                    "x_opencti_created_by_ref": self.author.id,
                },
            )
            objects.append(user_account)
            object_refs.append(user_account.id)

            # --- Indicator for breached credential ---
            indicator_value = email or username
            if indicator_value:
                if email and "@" in email:
                    pattern = f"[email-addr:value = '{self._escape_stix_value(email)}']"
                    indicator_name = f"Breached credential: {email}"
                else:
                    # Fall back to the email when there is no username (the email
                    # may be present but lack an "@"). indicator_value is truthy
                    # here, so username-or-email is guaranteed non-empty and the
                    # pattern is never an empty/constant string — an empty pattern
                    # would collapse unrelated records onto one Indicator id. This
                    # mirrors the UserAccount account_login below.
                    account_login = username or email
                    pattern = (
                        "[user-account:account_login = "
                        f"'{self._escape_stix_value(account_login)}']"
                    )
                    indicator_name = f"Breached credential: {account_login}"

                # Derive the Indicator id from its STIX pattern via the pycti
                # generator so the same credential pattern de-duplicates across
                # connectors (not just within this one).
                indicator_id = Indicator.generate_id(pattern)

                indicator = stix2.Indicator(
                    id=indicator_id,
                    name=indicator_name,
                    description=(
                        f"Credential exposed in data breach. "
                        f"Source: {breach_source}. Domain: {domain}."
                    ),
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=created,
                    created_by_ref=self.author.id,
                    external_references=[ext_ref],
                    labels=["breached-credential", "ctm360-cbs"],
                    custom_properties={"x_opencti_score": 80},
                )
                objects.append(indicator)
                object_refs.append(indicator_id)

                # Indicator --based-on--> EmailAddress or UserAccount
                if email and "@" in email:
                    objects.append(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator_id, email_obs.id
                            ),
                            relationship_type="based-on",
                            source_ref=indicator_id,
                            target_ref=email_obs.id,
                            created_by_ref=self.author.id,
                        )
                    )

                # Indicator --based-on--> UserAccount
                objects.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "based-on", indicator_id, user_account.id
                        ),
                        relationship_type="based-on",
                        source_ref=indicator_id,
                        target_ref=user_account.id,
                        created_by_ref=self.author.id,
                    )
                )

            # The Note id is seeded from stable content fields rather than
            # pycti's Note.generate_id(created, content): `created` falls back to
            # import time when the CBS record has no date, so a generator keyed on
            # it would mint a fresh Note every run and duplicate the same breach.
            note_seed = f"cbs-breach-{cred_id}-{email}-{username}"
            note_id = f"note--{uuid.uuid5(uuid.NAMESPACE_URL, note_seed)}"
            note = stix2.Note(
                id=note_id,
                content=(
                    f"Breached credential detected. Source: {breach_source}. "
                    f"Email: {email}, Username: {username}, Domain: {domain}."
                ),
                created=created,
                created_by_ref=self.author.id,
                external_references=[ext_ref],
                object_refs=object_refs,
                custom_properties={
                    "x_opencti_score": 80,
                },
            )
            objects.append(note)

        return objects

    def card_leaks_to_stix(self, cards: list) -> list:
        objects = [self.author]
        for card in cards:
            bank = card.get("bank_name", "Unknown")
            created = normalize_timestamp(card.get("date"))
            # Deterministic fallback so the Note id stays stable across runs.
            card_id = card.get("id") or self._stable_fallback_id(
                "cardleak", bank, card.get("date")
            )

            ext_ref = self._ext_ref("CTM360-CyberBlindSpot", card_id)

            note_seed = f"cbs-cardleak-{card_id}"
            note_id = f"note--{uuid.uuid5(uuid.NAMESPACE_URL, note_seed)}"
            note = stix2.Note(
                id=note_id,
                content=(
                    f"Payment card leak detected by CTM360 CyberBlindSpot. "
                    f"Bank: {bank}. Card details redacted for security."
                ),
                created=created,
                created_by_ref=self.author.id,
                external_references=[ext_ref],
                object_refs=[self.author.id],
                custom_properties={
                    "x_opencti_score": 90,
                },
            )
            objects.append(note)

        return objects

    def domain_protection_to_stix(self, findings: list) -> list:
        objects = [self.author]
        for finding in findings:
            domain = finding.get("domain", "")
            finding_type = finding.get("type", "Unknown")
            risk_score = finding.get("risk_score", 50)
            status = finding.get("finding_status", "unknown")
            ip_address = finding.get("ip_address", "")
            created = normalize_timestamp(finding.get("created_date"))
            # Deterministic fallback so the Indicator id stays stable across
            # runs when the API omits an explicit id.
            finding_id = finding.get("id") or self._stable_fallback_id(
                "domainprot", domain, finding_type
            )

            ext_ref = self._ext_ref("CTM360-CyberBlindSpot", finding_id)
            score = min(int(risk_score), 100) if risk_score else 50

            if domain:
                domain_obs = stix2.DomainName(
                    value=domain,
                    custom_properties={
                        "x_opencti_score": score,
                        "x_opencti_created_by_ref": self.author.id,
                    },
                )
                objects.append(domain_obs)

                pattern = f"[domain-name:value = '{self._escape_stix_value(domain)}']"
                indicator = stix2.Indicator(
                    id=Indicator.generate_id(pattern),
                    name=f"Suspicious domain: {domain}",
                    description=(
                        f"Domain protection finding: {finding_type}. "
                        f"Risk score: {risk_score}. Status: {status}."
                    ),
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=created,
                    created_by_ref=self.author.id,
                    external_references=[ext_ref],
                    custom_properties={"x_opencti_score": score},
                )
                objects.append(indicator)

                objects.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "based-on", indicator.id, domain_obs.id
                        ),
                        relationship_type="based-on",
                        source_ref=indicator.id,
                        target_ref=domain_obs.id,
                        created_by_ref=self.author.id,
                    )
                )

            if ip_address:
                try:
                    ipaddress.ip_address(ip_address)
                    ip_obs = stix2.IPv4Address(
                        value=ip_address,
                        custom_properties={
                            "x_opencti_score": score,
                            "x_opencti_created_by_ref": self.author.id,
                        },
                    )
                    objects.append(ip_obs)
                    if domain:
                        objects.append(
                            stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "resolves-to", domain_obs.id, ip_obs.id
                                ),
                                relationship_type="resolves-to",
                                source_ref=domain_obs.id,
                                target_ref=ip_obs.id,
                                created_by_ref=self.author.id,
                            )
                        )
                except ValueError:
                    pass

        return objects
