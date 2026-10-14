import base64
import copy
import datetime
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import ClassVar

import boto3
import pytz
import stix2
from connectors_sdk.models.enums import TLPLevel
from pycti import (
    CourseOfAction,
    Identity,
    Indicator,
    Infrastructure,
    Malware,
    MarkingDefinition,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
    resolve_aliases_field,
)
from settings import ConnectorSettings

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

# Files are all held in memory during a run so that versions can be compared
MAX_FILES_PER_RUN = 1000
S3_DOWNLOAD_WORKERS = 8
PLATFORM_LOOKUP_BATCH_SIZE = 100
# A previous work that makes no progress for this long is not waited for anymore
WORK_STALL_TIMEOUT = datetime.timedelta(hours=1)
PENDING_WORKS_STATE_KEY = "pending_works"
# What an outdated vulnerability is reduced to: enough to resolve the references of its
# file, nothing the platform would overwrite
REFERENCE_KEYS = (
    "type",
    "spec_version",
    "id",
    "name",
    "created_by_ref",
    "object_marking_refs",
)


def parse_stix_timestamp(value):
    """Parse a STIX timestamp into a timezone-aware datetime (UTC when no offset)."""
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def union_lists(newest, older):
    """Items of `newest` first, then the items of `older` that `newest` lacks."""
    merged = []
    seen = set()
    for item in [*newest, *older]:
        marker = json.dumps(item, sort_keys=True, default=str)
        if marker not in seen:
            seen.add(marker)
            merged.append(copy.deepcopy(item))
    return merged


def merge_versions(versions):
    """
    Merge the versions of one STIX object, given oldest first.

    This is the result the platform would reach by applying the versions in order:
    single values come from the newest version that has them, list values (labels,
    external references, aliases, history entries...) are the union of all versions.
    """
    merged = {}
    for version in versions:
        for key, value in version.items():
            previous = merged.get(key)
            if isinstance(value, list) and isinstance(previous, list):
                merged[key] = union_lists(value, previous)
            else:
                merged[key] = copy.deepcopy(value)
    return merged


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
    S3_MARKINGS: ClassVar[dict[TLPLevel, stix2.MarkingDefinition]] = {
        TLPLevel.CLEAR: stix2.MarkingDefinition(
            id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
            definition_type="statement",
            definition={"statement": "custom"},
            custom_properties={
                "x_opencti_definition_type": "TLP",
                "x_opencti_definition": "TLP:CLEAR",
            },
        ),
        TLPLevel.WHITE: stix2.TLP_WHITE,
        TLPLevel.GREEN: stix2.TLP_GREEN,
        TLPLevel.AMBER: stix2.TLP_AMBER,
        TLPLevel.AMBER_STRICT: stix2.MarkingDefinition(
            id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
            definition_type="statement",
            definition={"statement": "custom"},
            custom_properties={
                "x_opencti_definition_type": "TLP",
                "x_opencti_definition": "TLP:AMBER+STRICT",
            },
        ),
        TLPLevel.RED: stix2.TLP_RED,
    }

    def __init__(self):
        # Instantiate the connector helper from config
        self.config = ConnectorSettings()
        self.helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())
        # Extra config
        self.s3_region = self.config.s3.region
        self.s3_endpoint_url = self.config.s3.endpoint_url or None
        self.s3_access_key_id = self.config.s3.access_key_id.get_secret_value()
        self.s3_secret_access_key = self.config.s3.secret_access_key.get_secret_value()
        self.s3_bucket_name = self.config.s3.bucket_name
        self.s3_author = self.config.s3.author or None
        try:
            marking_level = TLPLevel(
                self.config.s3.marking.strip().lower().removeprefix("tlp:")
            )
            self.s3_marking = self.S3_MARKINGS[marking_level]
        except (KeyError, ValueError):
            self.helper.log_warning(
                f"Unrecognized marking definition {self.config.s3.marking}, defaulting to TLP:GREEN"
            )
            self.s3_marking = stix2.TLP_GREEN
        self.s3_attach_original_file = self.config.s3.attach_original_file
        self.s3_delete_after_import = self.config.s3.delete_after_import
        self.s3_no_split_bundles = self.config.s3.no_split_bundles
        self.s3_bucket_prefixes = self.config.s3.bucket_prefixes

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
        return self.config.connector.duration_period.total_seconds()

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

    @staticmethod
    def generate_standard_id(obj):
        """Return the deterministic STIX ID `obj` is sent under, None to keep its own."""
        obj_type = obj.get("type")
        if obj_type == "vulnerability":
            return Vulnerability.generate_id(obj["name"])
        if obj_type == "infrastructure":
            return Infrastructure.generate_id(obj["name"])
        if obj_type == "identity":
            return Identity.generate_id(obj["name"], obj["identity_class"])
        if obj_type == "course-of-action":
            return CourseOfAction.generate_id(obj["name"], obj.get("x_mitre_id"))
        if obj_type == "malware":
            return Malware.generate_id(obj["name"])
        if obj_type == "indicator":
            return Indicator.generate_id(obj["pattern"])
        return None

    def get_version(self, obj):
        """
        Return (entity id, modified) for an object that carries a version, None otherwise.

        Relationships are left out: their final ID only exists once `fix_bundle` has
        rewritten them, and the platform only adds them.
        """
        if obj.get("type") == "relationship" or not obj.get("modified"):
            return None
        try:
            modified = parse_stix_timestamp(obj["modified"])
        except (TypeError, ValueError):
            self.helper.log_warning(
                f"[VERSIONING] Unreadable 'modified' on {obj.get('id')}: "
                f"{obj.get('modified')!r}, sent as received"
            )
            return None
        return self.generate_standard_id(obj) or obj.get("id"), modified

    def resolve_versions(self, bundles):
        """
        Make every copy of an entity found in the run carry the newest content.

        The same entity can be published several times before a run picks the files
        up. Each file is sent as its own bundle and workers apply bundles in parallel,
        so the order of arrival on the platform is not the order of sending. Every copy
        is therefore replaced by the merge of all the versions of the run (see
        `merge_versions`): whatever the order, the newest version wins. Each copy keeps
        its file-local ID so that the relationships of its file still resolve.

        Args:
            bundles: Parsed STIX bundles of the run, oldest file first. Objects are
                updated in place.
        """
        copies = {}
        for data in bundles:
            for obj in data.get("objects") or []:
                version = self.get_version(obj)
                if version is not None:
                    entity_id, modified = version
                    copies.setdefault(entity_id, []).append((modified, obj))

        for entity_id, versions in copies.items():
            if len(versions) < 2:
                continue
            # sorted() is stable: on equal `modified`, the most recent file wins
            ordered = [obj for _, obj in sorted(versions, key=lambda v: v[0])]
            merged = merge_versions(ordered)
            self.helper.log_info(
                f"[VERSIONING] '{merged.get('name', entity_id)}' ({entity_id}): "
                f"{len(versions)} versions in this run "
                f"(modified: {', '.join(obj['modified'] for obj in ordered)}), "
                f"all copies sent with the newest one"
            )
            for obj in ordered:
                local_id = obj["id"]
                obj.clear()
                obj.update(copy.deepcopy(merged))
                obj["id"] = local_id

    def fetch_platform_modified_at(self, standard_ids):
        """
        Read x_opencti_modified_at of the vulnerabilities already in the platform.

        One query per PLATFORM_LOOKUP_BATCH_SIZE vulnerabilities. When a query fails, its
        vulnerabilities are treated as absent from the platform and sent as received.

        Returns:
            dict: standard ID -> x_opencti_modified_at, for the vulnerabilities that have one
        """
        wanted = set(standard_ids)
        found = {}
        for start in range(0, len(standard_ids), PLATFORM_LOOKUP_BATCH_SIZE):
            batch = standard_ids[start : start + PLATFORM_LOOKUP_BATCH_SIZE]
            try:
                vulnerabilities = self.helper.api.vulnerability.list(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "ids", "values": batch, "mode": "or"}],
                        "filterGroups": [],
                    },
                    first=PLATFORM_LOOKUP_BATCH_SIZE,
                    getAll=True,
                    customAttributes="""
                        id
                        standard_id
                        x_opencti_stix_ids
                        x_opencti_modified_at
                    """,
                )
            except Exception as e:
                self.helper.log_warning(
                    f"[VERSIONING] Failed to read {len(batch)} vulnerability(ies) from the "
                    f"platform, sent as received: {type(e).__name__}: {e}"
                )
                continue
            # A standard ID match wins over a match on an alias STIX ID
            for vulnerability in sorted(
                vulnerabilities or [], key=lambda v: v.get("standard_id") in wanted
            ):
                modified_at = vulnerability.get("x_opencti_modified_at")
                if not modified_at:
                    continue
                for candidate in [
                    *(vulnerability.get("x_opencti_stix_ids") or []),
                    vulnerability.get("standard_id"),
                ]:
                    if candidate in wanted:
                        found[candidate] = modified_at
        return found

    def supersede_outdated_vulnerabilities(self, bundles):
        """
        Reduce the vulnerabilities that are older than the platform's to a reference.

        The platform overwrites the fields of an entity with any upsert of equal or
        higher confidence, whatever its version, so an outdated vulnerability must not
        be sent. Its reference still carries the relationships and the other objects of
        its file, which the platform only adds. Its Title, Analysis and History notes
        are not generated: their IDs do not change between versions, so they would
        overwrite the newer notes.

        Args:
            bundles: Parsed STIX bundles of the run. Objects are updated in place.
        """
        received = {}
        for data in bundles:
            for obj in data.get("objects") or []:
                if (
                    obj.get("type") == "vulnerability"
                    and obj.get("name")
                    and obj.get("modified")
                ):
                    standard_id = Vulnerability.generate_id(obj["name"])
                    received.setdefault(standard_id, []).append(obj)
        if not received:
            return

        platform_versions = self.fetch_platform_modified_at(list(received))
        outdated = 0
        for standard_id, objs in received.items():
            platform_modified = platform_versions.get(standard_id)
            if not platform_modified:
                continue
            for obj in objs:
                try:
                    is_outdated = parse_stix_timestamp(
                        platform_modified
                    ) > parse_stix_timestamp(obj["modified"])
                except (TypeError, ValueError):
                    continue
                if not is_outdated:
                    continue
                outdated += 1
                self.helper.log_info(
                    f"[VERSIONING] '{obj['name']}': the platform holds a newer version "
                    f"(x_opencti_modified_at={platform_modified}) than the received one "
                    f"(modified={obj['modified']}), only its relationships and related "
                    f"objects are sent"
                )
                reference = {key: obj[key] for key in REFERENCE_KEYS if key in obj}
                obj.clear()
                obj.update(reference)
        self.helper.log_info(
            f"[VERSIONING] {len(received)} vulnerability(ies) checked against the "
            f"platform, {outdated} outdated copy(ies) reduced to a reference"
        )

    @staticmethod
    def rewrite_stix_ids(objects):
        # First pass: Build ID mapping for objects that need new IDs
        id_mapping = {}

        for obj in objects:
            new_id = S3Connector.generate_standard_id(obj)
            if new_id is not None:
                id_mapping[obj["id"]] = new_id

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

    def parse_bundle(self, content, file_name=None):
        """Parse a file's content, None when it is not valid JSON."""
        # Skip invalid JSON files (Accenture sometimes sends bad data)
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            self.helper.log_warning(
                f"Invalid JSON in file '{file_name}', skipping: {e}"
            )
            return None

    def fix_bundle(self, bundle, file_name=None, original_content=None):
        """
        Process and fix a STIX bundle.

        Args:
            bundle: The STIX bundle, parsed (dict) or as content (bytes or string)
            file_name: Original S3 file name (used for x_opencti_files attachment)
            original_content: Original file content as bytes (used for x_opencti_files attachment)

        Returns:
            str: JSON string of the STIX bundle, or None if nothing to process
        """
        included_entities = []
        new_bundle_objects = []

        if isinstance(bundle, dict):
            data = bundle
        else:
            data = self.parse_bundle(bundle, file_name)
            if data is None:
                return None

        if "objects" not in data or not data["objects"]:
            self.helper.log_warning("Bundle has no objects to process")
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

    def list_files(self, prefix):
        """
        List the files of a prefix, oldest first, at most MAX_FILES_PER_RUN.

        S3 lists keys in alphabetical order, 1000 per call: ordering on the upload date
        keeps the files of a large push in publication order across runs.
        """
        paginator = self.s3_client.get_paginator("list_objects_v2")
        files = []
        for page in paginator.paginate(Bucket=self.s3_bucket_name, Prefix=prefix):
            files.extend(page.get("Contents", []))
        files.sort(key=lambda f: (f["LastModified"], f["Key"]))
        self.helper.log_info(f"{len(files)} file(s) found in S3 prefix '{prefix}'")
        if len(files) > MAX_FILES_PER_RUN:
            self.helper.log_info(
                f"Processing the {MAX_FILES_PER_RUN} oldest file(s) of S3 prefix "
                f"'{prefix}' in this run, the next runs will take the rest"
            )
        return files[:MAX_FILES_PER_RUN]

    def download_file(self, key):
        return self.s3_client.get_object(Bucket=self.s3_bucket_name, Key=key)[
            "Body"
        ].read()

    def has_pending_works(self):
        """
        Tell whether a work sent by a previous run is still being ingested.

        Workers apply the bundles of a queue in parallel: a version sent while an older
        one still waits in the queue can be applied first, and then overwritten. New
        files therefore stay in the bucket until the previous works are complete. The
        next run compares them with what the platform then holds.
        A work that makes no progress for WORK_STALL_TIMEOUT is not waited for anymore.
        """
        state = self.helper.get_state() or {}
        pending = state.get(PENDING_WORKS_STATE_KEY) or []
        if not pending:
            return False

        now = datetime.datetime.now(pytz.UTC)
        still_pending = []
        for entry in pending:
            work_id = entry.get("work_id")
            work = self.helper.api.work.get_work(work_id) if work_id else None
            if not work or work.get("status") == "complete":
                continue
            tracking = work.get("tracking") or {}
            expected = int(tracking.get("import_expected_number") or 0)
            processed = int(tracking.get("import_processed_number") or 0)
            # The run that sent this work is over: every bundle it sent is expected
            if processed >= expected:
                continue
            progress_at = entry.get("progress_at")
            if processed != entry.get("processed") or not progress_at:
                entry["processed"] = processed
                entry["progress_at"] = now.isoformat()
            elif now - parse_stix_timestamp(progress_at) > WORK_STALL_TIMEOUT:
                self.helper.log_warning(
                    f"Work {work_id} made no progress since {progress_at} "
                    f"({processed}/{expected} bundle(s) processed), not waiting for it "
                    f"anymore"
                )
                continue
            self.helper.log_info(
                f"Work {work_id} of a previous run is still in progress "
                f"({processed}/{expected} bundle(s) processed)"
            )
            still_pending.append(entry)

        state[PENDING_WORKS_STATE_KEY] = still_pending
        self.helper.set_state(state)
        return len(still_pending) > 0

    def register_pending_work(self, work_id):
        if work_id is None:
            return
        state = self.helper.get_state() or {}
        state.setdefault(PENDING_WORKS_STATE_KEY, []).append(
            {
                "work_id": work_id,
                "processed": 0,
                "progress_at": datetime.datetime.now(pytz.UTC).isoformat(),
            }
        )
        self.helper.set_state(state)
        # The state is otherwise saved on the next ping, after bundles were sent
        self.helper.force_ping()

    def process(self):
        """
        Process the STIX files of the S3 bucket.

        VERSIONING STRATEGY:
        - A run starts only once the works sent by the previous run are complete, so a
          version is never applied before an older one still waiting in the queue
        - Each prefix is processed oldest file first, at most MAX_FILES_PER_RUN per run
        - All the versions of an entity found in the run are merged: every bundle that
          contains the entity carries its newest content
        - Vulnerabilities older than the version held by the platform are reduced to a
          reference, their relationships and related objects are still sent

        FAIL-FAST STRATEGY:
        - Each file is deleted only after its bundle was successfully sent
        - If ANY error occurs during processing, the connector crashes completely
        - This ensures no file is ever deleted without successful processing
        - Platform team will be alerted when the connector crashes
        """
        if self.has_pending_works():
            self.helper.log_info(
                "Waiting for the works of the previous run to complete before "
                "processing new files"
            )
            return

        files_by_prefix = {}
        for prefix in self.s3_bucket_prefixes:
            self.helper.connector_logger.info(
                f"Listing files in S3 bucket '{self.s3_bucket_name}' with prefix '{prefix}'"
            )
            listed = self.list_files(prefix)
            # If a download fails, connector crashes - no file is deleted
            with ThreadPoolExecutor(max_workers=S3_DOWNLOAD_WORKERS) as executor:
                contents = list(
                    executor.map(self.download_file, [f["Key"] for f in listed])
                )
            files_by_prefix[prefix] = [
                {
                    "key": listed_file["Key"],
                    "last_modified": listed_file["LastModified"],
                    "content": content if self.s3_attach_original_file else None,
                    "data": self.parse_bundle(content, listed_file["Key"]),
                }
                for listed_file, content in zip(listed, contents)
            ]

        run_files = sorted(
            (s3_file for files in files_by_prefix.values() for s3_file in files),
            key=lambda s3_file: (s3_file["last_modified"], s3_file["key"]),
        )
        bundles = [
            s3_file["data"]
            for s3_file in run_files
            if isinstance(s3_file["data"], dict)
        ]
        self.resolve_versions(bundles)
        self.supersede_outdated_vulnerabilities(bundles)

        for prefix, files in files_by_prefix.items():
            if not files:
                continue

            # Built before the first send: note keys depend on the notes in the platform
            for s3_file in files:
                s3_file["bundle"] = (
                    self.fix_bundle(
                        s3_file["data"],
                        file_name=s3_file["key"],
                        original_content=s3_file["content"],
                    )
                    if isinstance(s3_file["data"], dict)
                    else None
                )

            # Work ID created lazily - only when we have valid content to send
            work_id = None
            processed_files = 0

            for s3_file in files:
                file_key = s3_file["key"]
                fixed_bundle = s3_file["bundle"]
                self.helper.log_info(f"Processing file: '{file_key}'")

                # Only process valid bundles (fix_bundle returns None or JSON string)
                if fixed_bundle is not None:
                    # Create work job only on first valid bundle (lazy initialization)
                    if work_id is None:
                        now = datetime.datetime.now(pytz.UTC)
                        friendly_name = (
                            f"S3/{prefix} run @ " + now.astimezone(pytz.UTC).isoformat()
                        )
                        # Multipart: the work completes once every bundle is processed
                        work_id = self.helper.api.work.initiate_work(
                            self.helper.connect_id, friendly_name, is_multipart=True
                        )
                        self.register_pending_work(work_id)

                    # Send bundle to OpenCTI
                    # If this fails, connector crashes - file is NOT deleted
                    self.helper.log_info(f"Sending STIX bundle from file: '{file_key}'")
                    self.helper.send_stix2_bundle(
                        bundle=fixed_bundle,
                        work_id=work_id,
                        no_split=self.s3_no_split_bundles,
                    )
                    processed_files += 1

                    # Optionally delete file from S3 after successful processing
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
            f"Starting S3 connector with {self.get_interval():g} seconds interval"
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
