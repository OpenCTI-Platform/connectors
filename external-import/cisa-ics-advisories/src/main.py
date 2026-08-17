import datetime
import email.utils
import json
import re
import ssl
import sys
import time
import traceback
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

import stix2
from models import ConfigLoader
from pycti import (
    Identity,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    Vulnerability,
)

# The RSS <description> for each ICS Advisory item embeds a GitHub blob-view
# link to the advisory's structured CSAF JSON document, e.g.:
#   https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-225-05.json
# We rewrite that to the equivalent raw.githubusercontent.com URL to fetch it.
_CSAF_LINK_RE = re.compile(
    r"https://github\.com/cisagov/CSAF/blob/(?P<ref>[^/]+)/(?P<path>[^\"]+\.json)"
)


class CisaIcsAdvisories:
    def __init__(self):
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(config=self.config.model_dump_pycti())

        self.duration_period = self.config.connector.duration_period
        self.feed_url = self.config.cisa_ics.feed_url
        self.csaf_org_raw_base = self.config.cisa_ics.csaf_org_raw_base
        self.max_advisories_per_run = self.config.cisa_ics.max_advisories_per_run
        self.tlp = self.config.cisa_ics.tlp

        self.created_by_stix = None
        self.tlp_marking = None
        self.org = "Cybersecurity and Infrastructure Security Agency"

    # ------------------------------------------------------------------ HTTP
    def retrieve_data(self, url: str) -> Optional[str]:
        """Retrieve a URL as text, or None on failure (logged, never raised)."""
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "OpenCTI-Connector-CISA-ICS-Advisories"})
            return (
                urllib.request.urlopen(request, context=ssl.create_default_context())
                .read()
                .decode("utf-8")
            )
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.log_error(f"Error retrieving url {url}: {urllib_error}")
        return None

    # ---------------------------------------------------------------- Feed
    def fetch_advisory_list(self) -> List[Dict]:
        """Parse the ICS Advisories RSS feed into [{id, title, link, pubDate, csaf_url}]."""
        raw = self.retrieve_data(self.feed_url)
        if raw is None:
            return []
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            self.helper.log_error(f"Failed to parse ICS Advisories RSS feed: {e}")
            return []

        advisories = []
        for item in root.findall(".//item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub_date = (item.findtext("pubDate") or "").strip()
            description = item.findtext("description") or ""

            match = _CSAF_LINK_RE.search(description)
            if not match or not link:
                continue

            advisory_id = link.rstrip("/").rsplit("/", 1)[-1].upper()
            csaf_url = f"{self.csaf_org_raw_base}{match.group('path')}"
            advisories.append(
                {
                    "id": advisory_id,
                    "title": title,
                    "link": link,
                    "pub_date": pub_date,
                    "csaf_url": csaf_url,
                }
            )
        return advisories

    # ---------------------------------------------------------------- CSAF
    def fetch_csaf(self, csaf_url: str) -> Optional[Dict]:
        raw = self.retrieve_data(csaf_url)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            self.helper.log_error(f"Failed to parse CSAF document {csaf_url}: {e}")
            return None

    @staticmethod
    def _to_iso8601(rfc2822_value: str) -> Optional[str]:
        """Convert an RSS pubDate (RFC 2822) to the STIX-canonical timestamp
        format (RFC 3339 / ISO 8601 with a literal 'Z'), or None if unparseable.

        stix2's own timestamp validation rejects Python's default
        ``datetime.isoformat()`` output (e.g. ``...+00:00``) -- it requires
        the ``Z`` suffix, confirmed against a real ``stix2.Report`` instance.
        """
        try:
            dt = email.utils.parsedate_to_datetime(rfc2822_value)
        except (TypeError, ValueError):
            return None
        if dt.tzinfo is not None:
            dt = dt.astimezone(datetime.timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _extract_products(csaf: Dict) -> Dict[str, Dict[str, str]]:
        """Walk product_tree vendor/product_name branches -> {product_id: {vendor, product}}."""
        products: Dict[str, Dict[str, str]] = {}

        def walk(node: Dict, vendor: Optional[str], product_name: Optional[str]):
            category = node.get("category")
            name = node.get("name")
            if category == "vendor":
                vendor = name
            elif category in ("product_name", "product_family"):
                product_name = name

            product = node.get("product")
            if product and product.get("product_id"):
                products[product["product_id"]] = {
                    "vendor": vendor or "Unknown Vendor",
                    "product": product_name or product.get("name") or "Unknown Product",
                }
            for branch in node.get("branches", []):
                walk(branch, vendor, product_name)

        for branch in csaf.get("product_tree", {}).get("branches", []):
            walk(branch, None, None)
        return products

    # -------------------------------------------------------------- Setup
    def set_created_by_stix(self):
        self.created_by_stix = stix2.Identity(
            id=Identity.generate_id(self.org, "organization"),
            identity_class="organization",
            name=self.org,
            description=(
                "The Cybersecurity and Infrastructure Security Agency is a United "
                "States federal agency, an operational component under Department "
                "of Homeland Security oversight."
            ),
            custom_properties={"x_opencti_organization_type": "vendor"},
        )

    def set_tlp_marking(self):
        self.helper.log_info("Retrieving TLP Data from CTI Service")
        marking = self.helper.api.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": [f"{self.tlp}"]}],
                "filterGroups": [],
            }
        )
        self.tlp_marking = marking["standard_id"]

    # --------------------------------------------------------------- Bundle
    def build_bundle(self, advisory: Dict, csaf: Dict) -> Optional[str]:
        document = csaf.get("document", {})
        tracking = document.get("tracking", {})
        title = document.get("title") or advisory["title"]
        advisory_id = tracking.get("id") or advisory["id"]
        release_date = (
            tracking.get("current_release_date")
            or self._to_iso8601(advisory["pub_date"])
            or datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        created_by_id = self.created_by_stix["id"]
        marking_id = self.tlp_marking

        products = self._extract_products(csaf)
        stix_objects: List = [self.created_by_stix]
        object_refs: List[str] = []
        seen_software: Dict[str, str] = {}  # "vendor|product" -> stix id
        seen_cves: Dict[str, str] = {}  # cve -> vuln stix id

        for vuln in csaf.get("vulnerabilities", []):
            cve = vuln.get("cve")
            if not cve:
                continue

            notes = vuln.get("notes", [])
            description = next(
                (n.get("text") for n in notes if n.get("category") == "summary"),
                notes[0].get("text") if notes else f"See {advisory['link']}",
            )
            cwe = vuln.get("cwe", {}) or {}

            if cve not in seen_cves:
                stix_vuln = stix2.Vulnerability(
                    id=Vulnerability.generate_id(cve),
                    name=cve,
                    description=description,
                    created_by_ref=created_by_id,
                    object_marking_refs=[marking_id],
                    external_references=[
                        {
                            "source_name": "cisa-ics-advisories",
                            "description": title,
                            "url": advisory["link"],
                            "external_id": advisory_id,
                        }
                    ],
                    custom_properties={
                        "x_opencti_cisa_ics_advisory": advisory_id,
                        **({"x_opencti_cwe": cwe.get("id")} if cwe.get("id") else {}),
                    },
                )
                stix_objects.append(stix_vuln)
                object_refs.append(stix_vuln["id"])
                seen_cves[cve] = stix_vuln["id"]
            vuln_id = seen_cves[cve]

            affected_ids = set(vuln.get("product_status", {}).get("known_affected", []))
            for pid in affected_ids:
                info = products.get(pid)
                if not info:
                    continue
                key = f"{info['vendor']}|{info['product']}"
                if key not in seen_software:
                    stix_org = stix2.Identity(
                        id=Identity.generate_id(info["vendor"], "organization"),
                        name=info["vendor"],
                        identity_class="organization",
                        description="Software Vendor",
                        created_by_ref=created_by_id,
                        object_marking_refs=[marking_id],
                        custom_properties={"x_opencti_organization_type": "vendor"},
                    )
                    stix_software = stix2.Software(
                        name=info["product"],
                        vendor=info["vendor"],
                        custom_properties={"created_by_ref": created_by_id},
                    )
                    software_vendor_rel = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to", stix_software["id"], stix_org["id"]
                        ),
                        relationship_type="related-to",
                        description="This software is maintained by",
                        source_ref=stix_software["id"],
                        target_ref=stix_org["id"],
                        created_by_ref=created_by_id,
                        object_marking_refs=[marking_id],
                    )
                    stix_objects.extend([stix_org, stix_software, software_vendor_rel])
                    object_refs.extend([stix_org["id"], stix_software["id"]])
                    seen_software[key] = stix_software["id"]

                software_id = seen_software[key]
                stix_objects.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id("has", software_id, vuln_id),
                        relationship_type="has",
                        source_ref=software_id,
                        target_ref=vuln_id,
                        created_by_ref=created_by_id,
                        object_marking_refs=[marking_id],
                    )
                )

        if not seen_cves:
            # Advisory with no CVE-bearing vulnerabilities (rare); nothing to import.
            return None

        stix_report = stix2.Report(
            id=Report.generate_id(title, release_date),
            name=f"{advisory_id}: {title}",
            description=f"CISA Industrial Control Systems Advisory {advisory_id}.",
            report_types=["vulnerability"],
            published=release_date,
            created_by_ref=created_by_id,
            object_marking_refs=[marking_id],
            object_refs=object_refs,
            external_references=[
                {
                    "source_name": "cisa-ics-advisories",
                    "url": advisory["link"],
                    "external_id": advisory_id,
                }
            ],
        )
        stix_objects.append(stix_report)

        return self.helper.stix2_create_bundle(stix_objects)

    # ---------------------------------------------------------------- Loop
    def process_data(self):
        try:
            current_state = self.helper.get_state() or {}
            # Keep insertion order explicit (oldest first) so trimming the
            # tracked-ids list is deterministic; a set() has no stable order,
            # so slicing one after list(...) would keep an arbitrary subset.
            seen_ids_order: List[str] = list(current_state.get("seen_advisory_ids", []))
            seen_ids = set(seen_ids_order)

            now = datetime.datetime.now(tz=datetime.timezone.utc)
            friendly_name = "CISA ICS Advisories run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)

            self.set_created_by_stix()
            self.set_tlp_marking()

            advisories = self.fetch_advisory_list()[: self.max_advisories_per_run]
            new_ids = []
            imported = 0

            for advisory in advisories:
                if advisory["id"] in seen_ids:
                    continue
                csaf = self.fetch_csaf(advisory["csaf_url"])
                if csaf is None:
                    self.helper.log_error(
                        f"Could not fetch CSAF for {advisory['id']}, skipping"
                    )
                    continue
                bundle = self.build_bundle(advisory, csaf)
                if bundle is not None:
                    self.helper.send_stix2_bundle(bundle, work_id=work_id)
                    imported += 1
                new_ids.append(advisory["id"])

            # Append in processing order and trim from the front (oldest) so
            # which 2000 ids are kept is deterministic across runs.
            seen_ids_order.extend(new_ids)
            trimmed = seen_ids_order[-2000:]
            message = f"Connector successfully run, {imported} advisories imported, {len(trimmed)} tracked"
            self.helper.log_info(message)
            self.helper.set_state({"seen_advisory_ids": trimmed})
            self.helper.api.work.to_processed(work_id, message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching CISA ICS Advisories...")
        self.helper.schedule_iso(
            message_callback=self.process_data, duration_period=self.duration_period
        )


if __name__ == "__main__":
    try:
        connector = CisaIcsAdvisories()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
