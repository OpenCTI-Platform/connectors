import uuid

import stix2
from connector.utils import extract_cves, normalize_timestamp
from pycti import (
    Identity,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    Vulnerability,
)


class ConverterToStix:
    """Convert CTM360 CYNA news items to STIX 2.1 objects."""

    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self.author = stix2.Identity(
            id=Identity.generate_id(name="CTM360 CYNA", identity_class="organization"),
            name="CTM360 CYNA",
            identity_class="organization",
            description="CTM360 Cyber News & Alerts platform",
        )

    def _ext_ref(self, source_name: str, external_id: str, url: str = None):
        """Create a STIX ExternalReference."""
        ref = {"source_name": source_name, "external_id": str(external_id)}
        if url:
            ref["url"] = url
        return stix2.ExternalReference(**ref)

    def news_to_stix(self, news_items: list[dict]) -> list:
        """Convert a list of CYNA news items to STIX objects.

        Each news item produces:
        - A Report object
        - ExternalReference to the source URL
        - Vulnerability objects for any CVE mentions (deduplicated)
        - Relationships between Report and Vulnerabilities

        Args:
            news_items: List of news item dicts from the CYNA API.

        Returns:
            List of STIX objects (Identity, Reports, Vulnerabilities, Relationships).
        """
        if not news_items:
            return []

        objects = [self.author]
        # Global CVE dedup — track CVE IDs already created in this batch
        global_cve_objects: dict[str, stix2.Vulnerability] = {}
        converted_count = 0
        skipped_count = 0

        for item in news_items:
            try:
                item_objects = self._convert_single_news_item(item, global_cve_objects)
                if item_objects:
                    objects.extend(item_objects)
                    converted_count += 1
                else:
                    # Item was intentionally skipped (e.g. no published_date).
                    skipped_count += 1
            except Exception as e:
                item_id = self._get_item_id(item)
                self.helper.connector_logger.warning(
                    "[CONVERTER] Skipping malformed news item",
                    meta={"item_id": item_id, "error": str(e)},
                )
                skipped_count += 1
                continue

        # Include the referenced TLP marking definition so the bundle is
        # self-contained (every Report/Relationship references TLP_WHITE and
        # cleanup_inconsistent_bundle would otherwise flag those references).
        if len(objects) > 1:
            objects.append(stix2.TLP_WHITE)

        self.helper.connector_logger.info(
            "[CONVERTER] Conversion complete",
            meta={
                "converted": converted_count,
                "skipped": skipped_count,
                "total_stix_objects": len(objects),
                "unique_cves": len(global_cve_objects),
            },
        )

        return objects

    def _convert_single_news_item(
        self, item: dict, global_cve_objects: dict[str, stix2.Vulnerability]
    ) -> list:
        """Convert a single news item to STIX objects.

        Args:
            item: News item dict with 'metadata' sub-dict.
            global_cve_objects: Shared dict for CVE deduplication across items.

        Returns:
            List of STIX objects for this item.
        """
        objects = []
        metadata = item.get("metadata", {})

        title = metadata.get("title", "Untitled CYNA News")
        description = metadata.get("description", "")
        link = metadata.get("link", "")
        published_date = metadata.get("published_date", "")
        # _id is at the top level of the item, NOT inside metadata
        item_id = item.get("_id", "")

        # A news item without a usable published date can't get a deterministic
        # Report id (Report.generate_id is keyed on name+published); importing it
        # would mint — and then re-update — a fresh Report on every run. A
        # numeric 0 is a valid epoch, so only None / blank strings are "missing".
        if isinstance(published_date, str):
            has_published = bool(published_date.strip())
        else:
            has_published = published_date is not None
        if not has_published:
            self.helper.connector_logger.warning(
                "[CONVERTER] Skipping news item with no published_date",
                meta={"item_id": item_id or "unknown", "title": title},
            )
            return []

        published_ts = normalize_timestamp(published_date)

        # Derive a deterministic fallback id from stable content when the API
        # omits `_id`, so the external reference stays stable across re-imports
        # instead of churning a fresh uuid4 on every run.
        if not item_id:
            item_id = (
                f"cyna-{uuid.uuid5(uuid.NAMESPACE_URL, f'{title}|{published_ts}')}"
            )

        # Build external references
        ext_refs = [self._ext_ref("CTM360-CYNA", item_id)]
        if link and link.startswith(("http://", "https://")):
            ext_refs.append(self._ext_ref("CTM360-CYNA-Source", item_id, url=link))

        # Build labels from content analysis
        labels = self._extract_labels(title, description)

        # Create the Report (deterministic id via the pycti generator)
        report_name = f"[CYNA] {title}"
        report_id = Report.generate_id(name=report_name, published=published_ts)

        # Collect object_refs — will add vulnerability refs below
        object_refs = [self.author.id]

        # Extract CVEs from title and description
        combined_text = f"{title} {description}"
        cve_ids = extract_cves(combined_text)

        report_vuln_objects = []
        for cve_id in cve_ids:
            if cve_id in global_cve_objects:
                vuln = global_cve_objects[cve_id]
            else:
                vuln = stix2.Vulnerability(
                    id=Vulnerability.generate_id(cve_id),
                    name=cve_id,
                    description=f"Vulnerability {cve_id} mentioned in CTM360 CYNA news",
                    created_by_ref=self.author.id,
                    external_references=[
                        self._ext_ref(
                            "cve",
                            cve_id,
                            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        )
                    ],
                    object_marking_refs=[stix2.TLP_WHITE.id],
                    custom_properties={
                        "x_opencti_score": 50,
                    },
                )
                global_cve_objects[cve_id] = vuln
                report_vuln_objects.append(vuln)

            object_refs.append(vuln.id)

            # Create relationship: Report --related-to--> Vulnerability
            rel = stix2.Relationship(
                id=StixCoreRelationship.generate_id("related-to", report_id, vuln.id),
                relationship_type="related-to",
                source_ref=report_id,
                target_ref=vuln.id,
                created_by_ref=self.author.id,
                object_marking_refs=[stix2.TLP_WHITE.id],
            )
            report_vuln_objects.append(rel)

        report = stix2.Report(
            id=report_id,
            name=report_name,
            description=description or f"CTM360 CYNA news: {title}",
            published=published_ts,
            created=published_ts,
            modified=published_ts,
            report_types=["threat-report"],
            labels=labels,
            external_references=ext_refs,
            created_by_ref=self.author.id,
            object_refs=object_refs,
            object_marking_refs=[stix2.TLP_WHITE.id],
            custom_properties={
                "x_opencti_score": 50,
            },
        )
        objects.append(report)
        objects.extend(report_vuln_objects)

        return objects

    def _extract_labels(self, title: str, description: str) -> list[str]:
        """Extract labels from news content based on keyword matching.

        Identifies content categories: CVE, ransomware, DDoS, data leak,
        threat actor, advisory, phishing, malware, APT.

        Args:
            title: News item title.
            description: News item description.

        Returns:
            List of label strings (lowercase).
        """
        labels = ["cyna"]
        combined = f"{title} {description}".lower()

        keyword_labels = {
            "cve": ["cve-", "vulnerability", "vulnerabilities"],
            "ransomware": ["ransomware", "ransom"],
            "ddos": ["ddos", "denial of service", "denial-of-service"],
            "data-leak": ["data leak", "data breach", "leaked data", "data exposure"],
            "threat-actor": ["threat actor", "threat group", "apt", "hacker group"],
            "advisory": ["advisory", "advisories", "bulletin"],
            "phishing": ["phishing", "spear-phishing"],
            "malware": ["malware", "trojan", "backdoor", "botnet"],
            "zero-day": ["zero-day", "0-day", "zero day"],
        }

        for label, keywords in keyword_labels.items():
            for kw in keywords:
                if kw in combined:
                    labels.append(label)
                    break

        return labels

    def _get_item_id(self, item) -> str:
        """Safely extract an item ID for logging.

        Tolerates non-dict items (e.g. a malformed API page containing a bare
        string) so the per-item skip path in ``news_to_stix`` cannot itself
        raise and abort the whole conversion.
        """
        if isinstance(item, dict):
            return item.get("_id", "unknown")
        return "unknown"
