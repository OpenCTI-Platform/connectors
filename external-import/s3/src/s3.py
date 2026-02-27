import base64
import datetime
import json
import os
import re
import time

import boto3
import pytz
import stix2
import yaml
from pycti import (
    CourseOfAction,
    Identity,
    Indicator,
    Infrastructure,
    Malware,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
    get_config_variable,
    resolve_aliases_field,
)

mapped_keys = [
    "x_severity",
    "x_alias",
    "x_title",
    "x_analysis",
    "x_cvss_v3",
    "x_cvss_v3_vector",
    "x_wormable",
    "x_zero_day",
    "x_notable_vuln",
    "x_name",
    "x_cwe",
    "x_cvss_v2",
    "x_cvss_v2_vector",
    "x_cvss_v2_temporal_score",
    "x_cvss_v3_temporal_score",
    "x_first_seen_active",
    "x_history",
    "x_acti_uuid",
    "x_product",
    "x_and_prior_versions",
    "x_credit",
]
ignored_keys = ["x_acti_guid", "x_version", "x_vendor", "x_opencti_files"]

# Pattern to match invisible/zero-width Unicode characters that can break URLs
INVISIBLE_CHARS_PATTERN = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00a0\u2060\u2061\u2062\u2063\u2064]"
)


def sanitize_url(url):
    """
    Remove invisible Unicode characters from URLs.
    These include BOM, zero-width spaces, and other non-printable characters
    that can be accidentally included in data but break URL processing.
    """
    if not url or not isinstance(url, str):
        return url
    # Remove invisible characters and strip whitespace
    return INVISIBLE_CHARS_PATTERN.sub("", url).strip()


class S3Connector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.s3_region = get_config_variable(
            "S3_REGION", ["s3", "region"], config, default="us-east-1"
        )
        self.s3_endpoint_url = get_config_variable(
            "S3_ENDPOINT_URL", ["s3", "endpoint_url"], config
        )
        self.s3_access_key_id = get_config_variable(
            "S3_ACCESS_KEY_ID", ["s3", "access_key_id"], config
        )
        self.s3_secret_access_key = get_config_variable(
            "S3_SECRET_ACCESS_KEY", ["s3", "secret_access_key"], config
        )
        self.s3_bucket_name = get_config_variable(
            "S3_BUCKET_NAME", ["s3", "bucket_name"], config
        )
        self.s3_author = get_config_variable("S3_AUTHOR", ["s3", "author"], config)
        s3_marking = get_config_variable(
            "S3_MARKING",
            ["s3", "marking"],
            config,
            default="TLP:GREEN",
        ).lower()
        # Only change to new marking definition if it matches the naming convention
        self.s3_marking = stix2.TLP_GREEN
        if s3_marking == "tlp:clear" or s3_marking == "tlp:white":
            self.s3_marking = stix2.TLP_WHITE
        elif s3_marking == "tlp:green":
            self.s3_marking = stix2.TLP_GREEN
        elif s3_marking == "tlp:amber":
            self.s3_marking = stix2.TLP_AMBER
        elif s3_marking == "tlp:red":
            self.s3_marking = stix2.TLP_RED
        else:
            self.helper.log_warning(
                "Unrecognized marking definition {m}, defaulting to TLP:GREEN".format(
                    m=s3_marking
                )
            )
        self.s3_interval = get_config_variable(
            "S3_INTERVAL", ["s3", "interval"], config, isNumber=True, default=30
        )
        self.s3_attach_original_file = get_config_variable(
            "S3_ATTACH_ORIGINAL_FILE",
            ["s3", "attach_original_file"],
            config,
            default=False,
        )
        self.s3_delete_after_import = get_config_variable(
            "S3_DELETE_AFTER_IMPORT",
            ["s3", "delete_after_import"],
            config,
            default=True,
        )
        self.s3_no_split_bundles = get_config_variable(
            "S3_NO_SPLIT_BUNDLES",
            ["s3", "no_split_bundles"],
            config,
            default=True,
        )
        bucket_prefixes = get_config_variable(
            "S3_BUCKET_PREFIXES",
            ["s3", "bucket_prefixes"],
            config,
            isNumber=False,
            default="ACI_TI,ACI_Vuln",
        )
        self.s3_bucket_prefixes = [x.strip() for x in bucket_prefixes.split(",")]

        # Create the identity
        self.identity = None
        if self.s3_author is not None:
            self.identity = self.helper.api.identity.create(
                type="Organization", name=self.s3_author
            )

        self.s3_client = boto3.client(
            "s3",
            aws_access_key_id=self.s3_access_key_id,
            aws_secret_access_key=self.s3_secret_access_key,
            endpoint_url=self.s3_endpoint_url,
            region_name=self.s3_region,
        )

    def get_interval(self):
        return int(self.s3_interval)

    def note_exists_by_abstract(self, abstract):
        """
        Check if a note with the given abstract already exists in the API.

        :param abstract: The abstract to search for
        :return: True if a note with this abstract exists, False otherwise
        """
        try:
            filters = {
                "mode": "and",
                "filters": [
                    {
                        "key": "attribute_abstract",
                        "values": [abstract],
                        "operator": "eq",
                    }
                ],
                "filterGroups": [],
            }
            notes = self.helper.api.note.list(filters=filters, first=1)
            return len(notes) > 0
        except Exception as e:
            self.helper.log_warning(
                f"Failed to check for existing note with abstract '{abstract}': {e}"
            )
            # On error, default to using simple key (consolidate behavior)
            return True

    def filter_outdated_vulnerabilities(self, data):
        """
        Pre-process the bundle to filter out vulnerabilities that are outdated
        compared to what already exists in the OpenCTI platform.

        For each vulnerability in the bundle, query the platform for its
        x_opencti_modified_at value. If the platform's value is more recent
        than the bundle vulnerability's 'modified' field, the vulnerability
        is considered outdated and is removed along with all relationships
        pointing to or from it.

        Args:
            data: Parsed JSON dict of the STIX bundle

        Returns:
            dict: The filtered bundle data
        """
        if "objects" not in data or not data["objects"]:
            return data

        # Count vulnerabilities in the bundle for context
        all_vulns = [o for o in data["objects"] if o.get("type") == "vulnerability"]
        total_objects = len(data["objects"])
        self.helper.log_info(
            f"[PRE-PROCESS] Starting outdated vulnerability check: "
            f"{len(all_vulns)} vulnerability(ies) in bundle ({total_objects} total objects)"
        )

        outdated_vuln_ids = set()

        for obj in data["objects"]:
            if obj.get("type") != "vulnerability":
                continue

            vuln_name = obj.get("name")
            vuln_modified = obj.get("modified")

            if not vuln_name or not vuln_modified:
                self.helper.log_info(
                    f"[PRE-PROCESS] Vulnerability '{vuln_name}' has no 'modified' field, "
                    f"skipping outdated check, will be ingested"
                )
                continue

            # Generate the deterministic STIX ID for this vulnerability
            vuln_standard_id = Vulnerability.generate_id(vuln_name)
            self.helper.log_info(
                f"[PRE-PROCESS] Checking '{vuln_name}': "
                f"bundle_id={obj['id']}, standard_id={vuln_standard_id}, "
                f"received_modified={vuln_modified}"
            )

            try:
                existing_vuln = self.helper.api.vulnerability.read(
                    id=vuln_standard_id,
                    customAttributes="""
                        id
                        x_opencti_modified_at
                    """,
                )

                if existing_vuln is None:
                    self.helper.log_info(
                        f"[PRE-PROCESS] '{vuln_name}': does not exist in platform "
                        f"(read returned None) -> KEPT, will be ingested"
                    )
                    continue

                platform_modified = existing_vuln.get("x_opencti_modified_at")

                if not platform_modified:
                    self.helper.log_info(
                        f"[PRE-PROCESS] '{vuln_name}': exists in platform but has no "
                        f"x_opencti_modified_at (returned keys: {list(existing_vuln.keys())}) "
                        f"-> KEPT, will be ingested"
                    )
                    continue

                # Parse to datetime for safe comparison (handles Z, +00:00, milliseconds, etc.)
                platform_dt = datetime.datetime.fromisoformat(
                    platform_modified.replace("Z", "+00:00")
                )
                received_dt = datetime.datetime.fromisoformat(
                    vuln_modified.replace("Z", "+00:00")
                )
                is_outdated = platform_dt > received_dt

                self.helper.log_info(
                    f"[PRE-PROCESS] '{vuln_name}': "
                    f"platform_x_opencti_modified_at='{platform_modified}' (parsed={platform_dt}), "
                    f"received_modified='{vuln_modified}' (parsed={received_dt}), "
                    f"is_outdated={is_outdated} "
                    f"-> {'FILTERED OUT' if is_outdated else 'KEPT'}"
                )

                if is_outdated:
                    outdated_vuln_ids.add(obj["id"])

            except Exception as e:
                self.helper.log_warning(
                    f"[PRE-PROCESS] '{vuln_name}': failed to check against platform: "
                    f"{type(e).__name__}: {e} -> KEPT, will proceed with ingestion"
                )

        if not outdated_vuln_ids:
            self.helper.log_info(
                f"[PRE-PROCESS] Complete: no outdated vulnerabilities found, "
                f"all {len(all_vulns)} vulnerability(ies) will be ingested"
            )
            return data

        # Filter out outdated vulnerabilities and their relationships
        filtered_objects = []
        removed_rels = 0

        for obj in data["objects"]:
            obj_id = obj.get("id", "unknown")
            obj_type = obj.get("type", "unknown")

            if obj_id in outdated_vuln_ids:
                self.helper.log_info(
                    f"[PRE-PROCESS] Removing vulnerability: '{obj.get('name')}' (id={obj_id})"
                )
                continue

            if obj_type == "relationship":
                source_ref = obj.get("source_ref", "")
                target_ref = obj.get("target_ref", "")
                rel_type = obj.get("relationship_type", "unknown")
                if source_ref in outdated_vuln_ids or target_ref in outdated_vuln_ids:
                    self.helper.log_info(
                        f"[PRE-PROCESS] Removing relationship: type='{rel_type}', "
                        f"source={source_ref}, target={target_ref}, id={obj_id}"
                    )
                    removed_rels += 1
                    continue

            filtered_objects.append(obj)

        kept_vulns = len(all_vulns) - len(outdated_vuln_ids)
        self.helper.log_info(
            f"[PRE-PROCESS] Complete: "
            f"{len(outdated_vuln_ids)} vulnerability(ies) filtered out, "
            f"{kept_vulns} vulnerability(ies) kept, "
            f"{removed_rels} relationship(s) removed, "
            f"{len(filtered_objects)}/{total_objects} objects remaining in bundle"
        )

        data["objects"] = filtered_objects
        return data

    @staticmethod
    def rewrite_stix_ids(objects):
        # First pass: Build ID mapping for objects that need new IDs
        id_mapping = {}

        for obj in objects:
            obj_type = obj.get("type")

            if obj_type == "vulnerability":
                old_id = obj["id"]
                new_id = Vulnerability.generate_id(obj["name"])
                id_mapping[old_id] = new_id

            elif obj_type == "infrastructure":
                old_id = obj["id"]
                new_id = Infrastructure.generate_id(obj["name"])
                id_mapping[old_id] = new_id

            elif obj_type == "identity":
                old_id = obj["id"]
                new_id = Identity.generate_id(obj["name"], obj["identity_class"])
                id_mapping[old_id] = new_id

            elif obj_type == "course-of-action":
                old_id = obj["id"]
                new_id = CourseOfAction.generate_id(obj["name"], obj.get("x_mitre_id"))
                id_mapping[old_id] = new_id

            elif obj_type == "malware":
                old_id = obj["id"]
                new_id = Malware.generate_id(obj["name"])
                id_mapping[old_id] = new_id

            elif obj_type == "indicator":
                old_id = obj["id"]
                new_id = Indicator.generate_id(obj["pattern"])
                id_mapping[old_id] = new_id

        # Second pass: Update all objects with new IDs and references
        for obj in objects:
            obj_type = obj.get("type")

            if obj_type == "relationship":
                # FIRST: Update references using the mapping
                source_ref = obj.get("source_ref")
                target_ref = obj.get("target_ref")

                if source_ref in id_mapping:
                    obj["source_ref"] = id_mapping[source_ref]
                if target_ref in id_mapping:
                    obj["target_ref"] = id_mapping[target_ref]

                # THEN: Generate relationship ID with the NEW/updated refs
                obj["id"] = StixCoreRelationship.generate_id(
                    obj["relationship_type"],
                    obj["source_ref"],
                    obj["target_ref"],
                    obj.get("start_time"),
                    obj.get("stop_time"),
                )

            # rewrite note object_refs stix_id
            elif obj_type == "note":
                for i, ref in enumerate(obj["object_refs"]):
                    if ref in id_mapping:
                        obj["object_refs"][i] = id_mapping[ref]

            elif obj_type in (
                "infrastructure",
                "identity",
                "course-of-action",
                "vulnerability",
                "malware",
                "indicator",
            ):
                # Update the object's ID from the mapping
                old_id = obj["id"]
                if old_id in id_mapping:
                    obj["id"] = id_mapping[old_id]

        return objects

    def fix_bundle(self, bundle, file_name=None, original_content=None):
        """
        Process and fix a STIX bundle.

        Args:
            bundle: The STIX bundle content (bytes or string)
            file_name: Original S3 file name (used for x_opencti_files attachment)
            original_content: Original file content as bytes (used for x_opencti_files attachment)

        Returns:
            str: JSON string of the STIX bundle, or None if nothing to process
        """
        included_entities = []
        new_bundle_objects = []

        # Parse bundle - skip invalid JSON files (Accenture sometimes sends bad data)
        try:
            data = json.loads(bundle)
        except json.JSONDecodeError as e:
            self.helper.log_warning(
                f"Invalid JSON in file '{file_name}', skipping: {e}"
            )
            return None

        if "objects" not in data or not data["objects"]:
            self.helper.log_warning("Bundle has no objects to process")
            return None

        # Pre-process: filter out vulnerabilities that are outdated compared to the platform
        data = self.filter_outdated_vulnerabilities(data)
        if not data.get("objects"):
            self.helper.log_info(
                "All objects were filtered out during pre-processing, nothing to ingest"
            )
            return None

        # Prepare file attachment if enabled
        file_attachment = None
        if self.s3_attach_original_file and file_name and original_content:
            # Extract just the filename from the S3 key (remove prefix path)
            base_filename = file_name.split("/")[-1] if "/" in file_name else file_name
            file_attachment = {
                "name": base_filename,
                "data": base64.b64encode(original_content).decode("utf-8"),
                "mime_type": "application/json",
                "no_trigger_import": True,
            }

        for obj in data["objects"]:
            included_entities.append(obj["id"])
        for obj in data["objects"]:
            # Attach original file to vulnerabilities if enabled
            if obj.get("type") == "vulnerability" and file_attachment:
                if "x_opencti_files" not in obj:
                    obj["x_opencti_files"] = []
                obj["x_opencti_files"].append(file_attachment)
                self.helper.connector_logger.debug(
                    f"Attached original file '{file_attachment['name']}' to vulnerability '{obj.get('name')}'"
                )

            for key in obj:
                if (
                    key.startswith("x_")
                    and key not in mapped_keys
                    and key not in ignored_keys
                ):
                    self.helper.log_error("Found non-mapped custom key: " + key)

            # Ensure modification date
            if "modified" in obj:
                obj["x_opencti_modified_at"] = obj["modified"]

            # Ensure author and marking
            if self.identity is not None and "created_by_ref" not in obj:
                obj["created_by_ref"] = self.identity["standard_id"]
            if "object_marking_refs" not in obj:
                obj["object_marking_refs"] = [self.s3_marking["id"]]

            # Sanitize URLs in external_references (remove invisible Unicode characters)
            if "external_references" in obj:
                sanitized_refs = []
                for ext_ref in obj["external_references"]:
                    if "url" in ext_ref:
                        ext_ref["url"] = sanitize_url(ext_ref["url"])
                    sanitized_refs.append(ext_ref)
                obj["external_references"] = sanitized_refs

            if "x_severity" in obj:
                # handle mapping of "x_severity" on Vulnerability object
                if obj["type"] == "vulnerability":
                    if obj["x_severity"] == 1:
                        obj["x_opencti_score"] = 20
                    elif obj["x_severity"] == 2:
                        obj["x_opencti_score"] = 40
                    elif obj["x_severity"] == 3:
                        obj["x_opencti_score"] = 60
                    elif obj["x_severity"] == 4:
                        obj["x_opencti_score"] = 80
                    elif obj["x_severity"] == 5:
                        obj["x_opencti_score"] = 100

                # handle mapping of "x_severity" on other objects (ex: Indicator)
                else:
                    if obj["x_severity"] == "high":
                        obj["x_opencti_score"] = 90
                    elif obj["x_severity"] == "medium":
                        obj["x_opencti_score"] = 60
                    elif obj["x_severity"] == "low":
                        obj["x_opencti_score"] = 30

            # Aliases - use correct field based on entity type
            if "x_alias" in obj:
                aliases_field = resolve_aliases_field(obj["type"])
                obj[aliases_field] = (
                    obj["x_alias"]
                    if isinstance(obj["x_alias"], list)
                    else [obj["x_alias"]]
                )

            # CVSS 2
            if "x_cvss_v2" in obj:
                obj["x_opencti_cvss_v2_base_score"] = obj["x_cvss_v2"]
            if "x_cvss_v2_temporal_score" in obj:
                obj["x_opencti_cvss_v2_temporal_score"] = obj[
                    "x_cvss_v2_temporal_score"
                ]
            if "x_cvss_v2_vector" in obj:
                obj["x_opencti_cvss_v2_vector_string"] = obj["x_cvss_v2_vector"]

            # CVSS3
            if "x_cvss_v3" in obj:
                obj["x_opencti_cvss_base_score"] = obj["x_cvss_v3"]
            if "x_cvss_v3_temporal_score" in obj:
                obj["x_opencti_cvss_temporal_score"] = obj["x_cvss_v3_temporal_score"]
            if "x_cvss_v3_vector" in obj:
                obj["x_opencti_cvss_vector_string"] = obj["x_cvss_v3_vector"]

            # CWE
            if "x_cwe" in obj:
                obj["x_opencti_cwe"] = [obj["x_cwe"]]

            # First seen active
            if "x_first_seen_active" in obj:
                obj["x_opencti_first_seen_active"] = obj["x_first_seen_active"]

            # Ad-hoc desc
            if "x_description" in obj:
                obj["x_opencti_description"] = obj["x_description"]

            # Title Note
            if obj.get("x_title", None) and obj.get("x_acti_uuid", None):
                # generate a unique note identifier that don't change in the time even of the obj_name change or x_title change
                # For non-CVE entries, include the name in the key to ensure uniqueness (unless a note with same abstract already exists)
                obj_name = obj.get("name", "")
                note_abstract = obj_name + " - Title"
                if obj_name.startswith("CVE-"):
                    note_key = obj.get("x_acti_uuid") + " - Title"
                elif self.note_exists_by_abstract(note_abstract):
                    # Note already exists with this abstract, use simple key to consolidate
                    note_key = obj.get("x_acti_uuid") + " - Title"
                else:
                    note_key = obj.get("x_acti_uuid") + " - " + obj_name + " - Title"
                note = stix2.Note(
                    id=Note.generate_id(obj["created"], note_key),
                    created=obj["created"],
                    abstract=note_abstract,
                    content=obj.get("x_title"),
                    object_refs=[obj["id"]],
                    object_marking_refs=[self.s3_marking["id"]],
                    created_by_ref=(
                        self.identity["standard_id"]
                        if self.identity is not None
                        else None
                    ),
                )
                # Serialize to dict so object_refs can be rewritten later
                new_bundle_objects.append(json.loads(note.serialize()))

            # Analysis Note
            if obj.get("x_analysis", None) and obj.get("x_acti_uuid", None):
                # generate a unique note identifier that don't change in the time even of the obj_name change or x_analysis change
                # For non-CVE entries, include the name in the key to ensure uniqueness (unless a note with same abstract already exists)
                obj_name = obj.get("name", "")
                note_abstract = obj_name + " - Analysis"
                if obj_name.startswith("CVE-"):
                    note_key = obj.get("x_acti_uuid") + " - Analysis"
                elif self.note_exists_by_abstract(note_abstract):
                    # Note already exists with this abstract, use simple key to consolidate
                    note_key = obj.get("x_acti_uuid") + " - Analysis"
                else:
                    note_key = obj.get("x_acti_uuid") + " - " + obj_name + " - Analysis"
                note = stix2.Note(
                    id=Note.generate_id(obj["created"], note_key),
                    created=obj["created"],
                    abstract=note_abstract,
                    content=obj["x_analysis"],
                    object_refs=[obj["id"]],
                    object_marking_refs=[self.s3_marking["id"]],
                    created_by_ref=(
                        self.identity["standard_id"]
                        if self.identity is not None
                        else None
                    ),
                )
                # Serialize to dict so object_refs can be rewritten later
                new_bundle_objects.append(json.loads(note.serialize()))

            # History Note
            if obj.get("x_history", None) and obj.get("x_acti_uuid", None):
                note_content = "| Timestamp | Comment |\n|---------|---------|\n"
                # Sort history entries by timestamp from most recent to oldest
                sorted_history = sorted(
                    obj.get("x_history"),
                    key=lambda h: h.get("timestamp", ""),
                    reverse=True,
                )
                for history in sorted_history:
                    comment = (history.get("comment") or "").strip()
                    timestamp = (history.get("timestamp") or "").strip()
                    note_content += f"| {timestamp} | {comment} |\n"

                # For non-CVE entries, include the name in the key to ensure uniqueness (unless a note with same abstract already exists)
                obj_name = obj.get("name", "")
                abstract = obj_name + " - History"
                if obj_name.startswith("CVE-"):
                    note_key = obj.get("x_acti_uuid") + " - History"
                elif self.note_exists_by_abstract(abstract):
                    # Note already exists with this abstract, use simple key to consolidate
                    note_key = obj.get("x_acti_uuid") + " - History"
                else:
                    note_key = obj.get("x_acti_uuid") + " - " + obj_name + " - History"
                note = stix2.Note(
                    id=Note.generate_id(obj["created"], note_key),
                    created=obj["created"],
                    abstract=abstract,
                    content=note_content,
                    object_refs=[obj["id"]],
                    object_marking_refs=[self.s3_marking["id"]],
                    created_by_ref=(
                        self.identity["standard_id"]
                        if self.identity is not None
                        else None
                    ),
                )
                # Serialize to dict so object_refs can be rewritten later
                new_bundle_objects.append(json.loads(note.serialize()))

            # Labels
            if "x_wormable" in obj and obj["x_wormable"]:
                if "labels" in obj:
                    obj["labels"].append("wormable")
                else:
                    obj["labels"] = ["wormable"]
            if "x_zero_day" in obj and obj["x_zero_day"]:
                if "labels" in obj:
                    obj["labels"].append("zero-day")
                else:
                    obj["labels"] = ["zero-day"]
            if "x_notable_vuln" in obj and obj["x_notable_vuln"]:
                if "labels" in obj:
                    obj["labels"].append("notable-vuln")
                else:
                    obj["labels"] = ["notable-vuln"]
            if "x_and_prior_versions" in obj and obj["x_and_prior_versions"]:
                if "labels" in obj:
                    obj["labels"].append("and-prior-versions")
                else:
                    obj["labels"] = ["and-prior-versions"]

            # x_product
            if "x_product" in obj:
                obj["x_opencti_product"] = obj["x_product"]

            # x_acti_uuid
            if "x_acti_uuid" in obj:
                external_ref = {
                    "source_name": "ACTI UUID",
                    "external_id": obj["x_acti_uuid"],
                }

                if "external_references" in obj:
                    obj["external_references"].append(external_ref)
                else:
                    obj["external_references"] = [external_ref]

            # Log external references count for debugging
            if "external_references" in obj and obj.get("type") == "vulnerability":
                ext_ref_count = len(obj["external_references"])
                ext_ref_sources = [
                    r.get("source_name", "unknown") for r in obj["external_references"]
                ]
                self.helper.connector_logger.debug(
                    f"Vulnerability '{obj.get('name')}' has {ext_ref_count} external_references: {ext_ref_sources}"
                )

            # x_credit mapping
            if "x_credit" in obj and obj["x_credit"]:
                individual_credit = stix2.Identity(
                    id=Identity.generate_id(
                        name=obj["x_credit"], identity_class="individual"
                    ),
                    name=obj["x_credit"],
                    identity_class="individual",
                    object_marking_refs=[self.s3_marking["id"]],
                )
                credit_relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", obj["id"], individual_credit.id
                    ),
                    relationship_type="related-to",
                    source_ref=obj["id"],
                    target_ref=individual_credit.id,
                    object_marking_refs=[self.s3_marking["id"]],
                    created_by_ref=(
                        self.identity["standard_id"]
                        if self.identity is not None
                        else None
                    ),
                )
                new_bundle_objects.append(json.loads(individual_credit.serialize()))
                new_bundle_objects.append(json.loads(credit_relationship.serialize()))

            # Relationships "has"
            if (
                obj["type"] == "relationship"
                and obj["relationship_type"] == "related-to"
                and obj["source_ref"].startswith("vulnerability")
                and obj["target_ref"].startswith("software")
            ):
                obj["relationship_type"] = "has"
                original_source_ref = obj["source_ref"]
                obj["source_ref"] = obj["target_ref"]
                obj["target_ref"] = original_source_ref

            # Relationship "remediates"
            if (
                obj["type"] == "relationship"
                and obj["relationship_type"] == "remediated-by"
                and obj["source_ref"].startswith("vulnerability")
                and obj["target_ref"].startswith("software")
            ):
                obj["relationship_type"] = "remediates"
                original_source_ref = obj["source_ref"]
                obj["source_ref"] = obj["target_ref"]
                obj["target_ref"] = original_source_ref

            # Relationship "remediates" in wrong direction
            if (
                obj["type"] == "relationship"
                and obj["relationship_type"] == "remediated-by"
                and obj["source_ref"].startswith("software")
                and obj["target_ref"].startswith("vulnerability")
            ):
                obj["relationship_type"] = "remediates"

            # Cleanup orphan relationships
            if (
                obj["type"] == "relationship"
                and obj["source_ref"] not in included_entities
            ):
                self.helper.log_warning(
                    "Removing relationship from "
                    + obj["source_ref"]
                    + " because object is not in bundle"
                )
                continue
            if (
                obj["type"] == "relationship"
                and obj["target_ref"] not in included_entities
            ):
                self.helper.log_warning(
                    "Removing relationship to "
                    + obj["target_ref"]
                    + " because object is not in bundle"
                )
                continue
            new_bundle_objects.append(obj)

        # Only create bundle if we have objects to process
        if len(new_bundle_objects) > 0:
            rewritten_bundle_objects = self.rewrite_stix_ids(new_bundle_objects)
            if self.s3_attach_original_file:
                # Create the STIX bundle
                bundle_dict = self.helper.stix2_create_bundle(rewritten_bundle_objects)
                # Serialize to JSON string and encode to bytes
                bundle_json = json.dumps(bundle_dict).encode("utf-8")
                # Now base64 encode the bytes
                file_attachment = {
                    "name": "opencti-bundle.json",
                    "data": base64.b64encode(bundle_json).decode("utf-8"),
                    "mime_type": "application/json",
                    "no_trigger_import": True,
                }
                for obj in data["objects"]:
                    if obj.get("type") == "vulnerability":
                        if "x_opencti_files" not in obj:
                            obj["x_opencti_files"] = []
                        obj["x_opencti_files"].append(file_attachment)
            return self.helper.stix2_create_bundle(rewritten_bundle_objects)

        return None

    def process(self):
        """
        Process all STIX files from the S3 bucket.

        FAIL-FAST STRATEGY:
        - Each file is processed and deleted immediately after successful ingestion
        - If ANY error occurs during processing, the connector crashes completely
        - This ensures no file is ever deleted without successful processing
        - Platform team will be alerted when the connector crashes
        """
        for prefix in self.s3_bucket_prefixes:
            self.helper.connector_logger.info(
                f"Listing files in S3 bucket '{self.s3_bucket_name}' with prefix '{prefix}'"
            )

            # List all objects in the bucket with the given prefix
            objects = self.s3_client.list_objects(
                Bucket=self.s3_bucket_name, Prefix=prefix
            )

            contents = objects.get("Contents", [])
            self.helper.log_info(
                f"{len(contents)} file(s) found in S3 prefix '{prefix}'"
            )

            if not contents:
                continue

            # Work ID created lazily - only when we have valid content to send
            work_id = None
            processed_files = 0

            for obj in contents:
                file_key = obj.get("Key")
                self.helper.log_info(f"Processing file: '{file_key}'")

                # Step 1: Fetch file content from S3
                # If this fails, connector crashes - file is NOT deleted
                data = self.s3_client.get_object(
                    Bucket=self.s3_bucket_name, Key=file_key
                )
                content = data["Body"].read()

                # Step 2: Parse and fix the STIX bundle
                # Pass file_key and content for optional file attachment to vulnerabilities
                fixed_bundle = self.fix_bundle(
                    content, file_name=file_key, original_content=content
                )

                # Only process valid bundles (fix_bundle returns None or JSON string)
                if fixed_bundle is not None:
                    # Create work job only on first valid bundle (lazy initialization)
                    if work_id is None:
                        now = datetime.datetime.now(pytz.UTC)
                        friendly_name = (
                            f"S3/{prefix} run @ " + now.astimezone(pytz.UTC).isoformat()
                        )
                        work_id = self.helper.api.work.initiate_work(
                            self.helper.connect_id, friendly_name
                        )

                    # Step 3: Send bundle to OpenCTI
                    # If this fails, connector crashes - file is NOT deleted
                    self.helper.log_info(f"Sending STIX bundle from file: '{file_key}'")
                    self.helper.send_stix2_bundle(
                        bundle=fixed_bundle,
                        work_id=work_id,
                        no_split=self.s3_no_split_bundles,
                    )
                    processed_files += 1

                    # Step 4: Optionally delete file from S3 after successful processing
                    if self.s3_delete_after_import:
                        self.helper.log_info(f"Deleting processed file: '{file_key}'")
                        self.s3_client.delete_object(
                            Bucket=self.s3_bucket_name, Key=file_key
                        )
                        self.helper.log_info(
                            f"Successfully processed and deleted file: '{file_key}'"
                        )
                    else:
                        self.helper.log_info(
                            f"Successfully processed file: '{file_key}' (kept in bucket for debug)"
                        )
                else:
                    # Empty/invalid bundle - optionally delete the file
                    if self.s3_delete_after_import:
                        self.helper.log_warning(
                            f"File '{file_key}' has no valid STIX content, deleting"
                        )
                        self.s3_client.delete_object(
                            Bucket=self.s3_bucket_name, Key=file_key
                        )
                    else:
                        self.helper.log_warning(
                            f"File '{file_key}' has no valid STIX content (kept in bucket for debug)"
                        )

            # Only finalize work if we actually processed something
            if work_id is not None:
                message = (
                    f"Connector successfully processed S3 prefix '{prefix}': "
                    f"{processed_files} file(s) ingested"
                )
                self.helper.log_info(message)
                self.helper.api.work.to_processed(work_id, message)
            else:
                self.helper.log_info(
                    f"No valid STIX content found in S3 prefix '{prefix}'"
                )

    def run(self):
        self.helper.log_info(
            f"Starting S3 connector with {self.get_interval()} seconds interval"
        )
        if self.helper.get_run_and_terminate():
            self.process()
            self.helper.force_ping()
        else:
            while True:
                self.process()
                time.sleep(self.get_interval())


if __name__ == "__main__":
    # FAIL-FAST: Any unhandled exception will crash the connector
    # This ensures files are never deleted without successful processing
    # The platform team will be alerted when the connector exits with error
    s3Connector = S3Connector()
    s3Connector.run()
