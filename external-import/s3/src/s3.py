import base64
import copy
import datetime
import heapq
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import ClassVar

import boto3
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
# Source fields that `fix_bundle` turns into labels: the platform only adds labels, so
# a flag raised by any version of an entity stays raised
ADDITIVE_FLAG_KEYS = (
    "x_wormable",
    "x_zero_day",
    "x_notable_vuln",
    "x_and_prior_versions",
)
# Source field that `fix_bundle` turns into aliases, given as a string or a list
ALIASES_SOURCE_KEY = "x_alias"

# Pattern to match invisible/zero-width Unicode characters that can break URLs
INVISIBLE_CHARS_PATTERN = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00a0\u2060\u2061\u2062\u2063\u2064]"
)

# Files are all held in memory during a run so that versions can be compared
MAX_FILES_PER_RUN = 1000
S3_DOWNLOAD_WORKERS = 8
PLATFORM_LOOKUP_BATCH_SIZE = 100
# A previous work that makes no progress for this long is considered stalled: it is
# released once the connector queue holds no message anymore
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
    """
    Parse a STIX timestamp into a timezone-aware datetime (UTC when no offset).

    Raises TypeError when the value is not a string and ValueError when it is not a
    timestamp, so that callers can treat both as an unreadable version.
    """
    if not isinstance(value, str):
        raise TypeError(f"Timestamp must be a string, got {type(value).__name__}")
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def is_reference_key(key):
    """
    Tell whether a STIX property is the ID of the object or a reference to another one.

    The IDs of a file are local to it until `rewrite_stix_ids` runs on that file alone,
    so a reference taken from another file's version of an object could not resolve.
    """
    return key == "id" or key.endswith("_ref") or key.endswith("_refs")


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


def oldest_timestamp(first, second):
    """The older of two STIX timestamps, `second` when either one is unreadable."""
    try:
        if parse_stix_timestamp(first) <= parse_stix_timestamp(second):
            return first
    except (TypeError, ValueError):
        pass
    return second


def as_list(value):
    """A list value as is, any other value as a one-item list."""
    return value if isinstance(value, list) else [value]


def merge_versions(versions):
    """
    Merge the versions of one STIX object, given oldest first.

    This is the result the platform would reach by applying the versions in order:
    single values come from the newest version that has them, list values (labels,
    external references, aliases, history entries...) are the union of all versions
    and `created` keeps its oldest value. The source fields that `fix_bundle` turns
    into additive platform fields follow the same rule: `x_alias` values are
    accumulated whether given as a string or a list, and a label flag raised by any
    version stays raised. The ID and the references (`*_ref`, `*_refs`) are left
    out: they are local to the file of each version (see `is_reference_key`).
    """
    merged = {}
    for version in versions:
        for key, value in version.items():
            if is_reference_key(key):
                continue
            previous = merged.get(key)
            if key == ALIASES_SOURCE_KEY and previous is not None:
                merged[key] = union_lists(as_list(value), as_list(previous))
            elif isinstance(value, list) and isinstance(previous, list):
                merged[key] = union_lists(value, previous)
            elif key in ADDITIVE_FLAG_KEYS and previous:
                continue
            elif key == "created" and previous is not None:
                merged[key] = oldest_timestamp(previous, value)
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
            self.helper.connector_logger.warning(
                "Unrecognized marking definition, defaulting to TLP:GREEN",
                {"marking": self.config.s3.marking},
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

    @staticmethod
    def generate_note_ids(obj, note_type):
        """
        Return the STIX ID of a Title, Analysis or History note of `obj`, and its aliases.

        Notes are matched on this ID while their content changes from one version to
        the next, so it only depends on the vulnerability, never on the platform state:
        - CVE notes are keyed on the ACTI UUID
        - other notes are also keyed on the vulnerability name, so that entries sharing
          an ACTI UUID keep their own notes

        Older versions of the connector keyed the notes of non-CVE entries on the ACTI
        UUID only. That ID is sent as an alias so those notes are updated in place
        instead of being duplicated, but only by the entry named by its ACTI UUID: the
        platform matches incoming entities on their aliases too, so an alias shared by
        entries sharing an ACTI UUID would collapse their notes into one. A name
        identifies a single vulnerability, so at most one entry claims that alias.

        :param obj: The vulnerability the note belongs to
        :param note_type: "Title", "Analysis" or "History"
        :return: The note STIX ID and the list of its alias STIX IDs
        """
        acti_uuid = obj["x_acti_uuid"]
        obj_name = obj.get("name", "")
        uuid_note_id = Note.generate_id(obj["created"], f"{acti_uuid} - {note_type}")
        if obj_name.startswith("CVE-"):
            return uuid_note_id, []
        name_note_id = Note.generate_id(
            obj["created"], f"{acti_uuid} - {obj_name} - {note_type}"
        )
        note_aliases = [uuid_note_id] if obj_name == acti_uuid else []
        return name_note_id, note_aliases

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
            self.helper.connector_logger.warning(
                "Unreadable 'modified' on an object, sent as received",
                {"id": obj.get("id"), "modified": repr(obj.get("modified"))},
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
        its file-local ID and references (author, markings, object refs...) so that
        every reference of its file still resolves once the IDs of that file are
        rewritten.

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
            self.helper.connector_logger.info(
                "Several versions of an entity in this run, all copies sent with the "
                "newest content",
                {
                    "name": merged.get("name"),
                    "entity_id": entity_id,
                    "versions": len(versions),
                    "modified": [obj["modified"] for obj in ordered],
                },
            )
            for obj in ordered:
                local = {
                    key: value for key, value in obj.items() if is_reference_key(key)
                }
                obj.clear()
                obj.update(copy.deepcopy(merged))
                obj.update(local)

    def fetch_platform_versions(self, standard_ids):
        """
        Read the version the platform holds of vulnerabilities: x_opencti_modified_at
        and created.

        One query per PLATFORM_LOOKUP_BATCH_SIZE vulnerabilities. When a query fails, its
        vulnerabilities are treated as absent from the platform and sent as received.

        Returns:
            dict: standard ID -> {"x_opencti_modified_at": ..., "created": ...}, for
                the vulnerabilities found in the platform (values may be None)
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
                        created
                    """,
                )
            except Exception as e:
                self.helper.connector_logger.warning(
                    "Failed to read vulnerabilities from the platform, sent as received",
                    {"count": len(batch), "error": f"{type(e).__name__}: {e}"},
                )
                continue
            # A standard ID match wins over a match on an alias STIX ID
            for vulnerability in sorted(
                vulnerabilities or [], key=lambda v: v.get("standard_id") in wanted
            ):
                version = {
                    "x_opencti_modified_at": vulnerability.get("x_opencti_modified_at"),
                    "created": vulnerability.get("created"),
                }
                for candidate in [
                    *(vulnerability.get("x_opencti_stix_ids") or []),
                    vulnerability.get("standard_id"),
                ]:
                    if candidate in wanted:
                        found[candidate] = version
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

        A newer vulnerability takes the `created` the platform holds when it is older
        than its own: the platform keeps the oldest creation date anyway, and the IDs
        of the notes derive from it, so the notes of every run are the same notes.

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

        platform_versions = self.fetch_platform_versions(list(received))
        outdated = 0
        for standard_id, objs in received.items():
            platform_version = platform_versions.get(standard_id)
            if not platform_version:
                continue
            platform_modified = platform_version.get("x_opencti_modified_at")
            platform_created = platform_version.get("created")
            for obj in objs:
                if platform_created and obj.get("created"):
                    obj["created"] = oldest_timestamp(platform_created, obj["created"])
                if not platform_modified:
                    continue
                try:
                    is_outdated = parse_stix_timestamp(
                        platform_modified
                    ) > parse_stix_timestamp(obj["modified"])
                except (TypeError, ValueError):
                    continue
                if not is_outdated:
                    continue
                outdated += 1
                self.helper.connector_logger.info(
                    "The platform holds a newer version of a vulnerability, only its "
                    "relationships and related objects are sent",
                    {
                        "name": obj["name"],
                        "platform_modified_at": platform_modified,
                        "received_modified": obj["modified"],
                    },
                )
                reference = {key: obj[key] for key in REFERENCE_KEYS if key in obj}
                obj.clear()
                obj.update(reference)
        self.helper.connector_logger.info(
            "Vulnerabilities checked against the platform",
            {"checked": len(received), "outdated_copies": outdated},
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
            self.helper.connector_logger.warning(
                "Invalid JSON in file, skipping", {"file": file_name, "error": str(e)}
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
            self.helper.connector_logger.warning(
                "Bundle has no objects to process", {"file": file_name}
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
                    "Attached original file to vulnerability",
                    {"file": file_attachment["name"], "name": obj.get("name")},
                )

            for key in obj:
                if (
                    key.startswith("x_")
                    and key not in mapped_keys
                    and key not in ignored_keys
                ):
                    self.helper.connector_logger.warning(
                        "Found non-mapped custom key", {"key": key}
                    )

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
                note_id, note_aliases = self.generate_note_ids(obj, "Title")
                note = stix2.Note(
                    id=note_id,
                    created=obj["created"],
                    abstract=obj.get("name", "") + " - Title",
                    content=obj.get("x_title"),
                    object_refs=[obj["id"]],
                    object_marking_refs=[self.s3_marking["id"]],
                    created_by_ref=(
                        self.identity["standard_id"]
                        if self.identity is not None
                        else None
                    ),
                    custom_properties={"x_opencti_stix_ids": note_aliases},
                )
                # Serialize to dict so object_refs can be rewritten later
                new_bundle_objects.append(json.loads(note.serialize()))

            # Analysis Note
            if obj.get("x_analysis", None) and obj.get("x_acti_uuid", None):
                note_id, note_aliases = self.generate_note_ids(obj, "Analysis")
                note = stix2.Note(
                    id=note_id,
                    created=obj["created"],
                    abstract=obj.get("name", "") + " - Analysis",
                    content=obj["x_analysis"],
                    object_refs=[obj["id"]],
                    object_marking_refs=[self.s3_marking["id"]],
                    created_by_ref=(
                        self.identity["standard_id"]
                        if self.identity is not None
                        else None
                    ),
                    custom_properties={"x_opencti_stix_ids": note_aliases},
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

                note_id, note_aliases = self.generate_note_ids(obj, "History")
                note = stix2.Note(
                    id=note_id,
                    created=obj["created"],
                    abstract=obj.get("name", "") + " - History",
                    content=note_content,
                    object_refs=[obj["id"]],
                    object_marking_refs=[self.s3_marking["id"]],
                    created_by_ref=(
                        self.identity["standard_id"]
                        if self.identity is not None
                        else None
                    ),
                    custom_properties={"x_opencti_stix_ids": note_aliases},
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
                    "External references of a vulnerability",
                    {
                        "name": obj.get("name"),
                        "count": ext_ref_count,
                        "sources": ext_ref_sources,
                    },
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
                self.helper.connector_logger.warning(
                    "Removing relationship because its source is not in the bundle",
                    {"source_ref": obj["source_ref"], "file": file_name},
                )
                continue
            if (
                obj["type"] == "relationship"
                and obj["target_ref"] not in included_entities
            ):
                self.helper.connector_logger.warning(
                    "Removing relationship because its target is not in the bundle",
                    {"target_ref": obj["target_ref"], "file": file_name},
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
        keeps the files of a large push in publication order across runs (the next
        runs reach the rest of the backlog as the processed files are deleted). Only
        the MAX_FILES_PER_RUN oldest entries are kept while the pages are read, so the
        memory used does not grow with the backlog of the prefix.
        """
        paginator = self.s3_client.get_paginator("list_objects_v2")
        total = 0

        def listed_files():
            nonlocal total
            for page in paginator.paginate(Bucket=self.s3_bucket_name, Prefix=prefix):
                for listed_file in page.get("Contents", []):
                    total += 1
                    yield listed_file

        files = heapq.nsmallest(
            MAX_FILES_PER_RUN,
            listed_files(),
            key=lambda f: (f["LastModified"], f["Key"]),
        )
        self.helper.connector_logger.info(
            "Files found in S3 prefix", {"prefix": prefix, "count": total}
        )
        if total > MAX_FILES_PER_RUN:
            self.helper.connector_logger.info(
                "Processing only the oldest files of the S3 prefix in this run",
                {"prefix": prefix, "processed": len(files), "total": total},
            )
        return files

    def download_file(self, key):
        return self.s3_client.get_object(Bucket=self.s3_bucket_name, Key=key)[
            "Body"
        ].read()

    def get_queue_messages_number(self):
        """
        Return the number of messages waiting in the queue of this connector.

        None when the platform does not report it (older platform, RabbitMQ management
        API unreachable, request failure).
        """
        try:
            connector = self.helper.api.connector.read(self.helper.connect_id) or {}
            messages_number = (connector.get("connector_queue_details") or {}).get(
                "messages_number"
            )
            return None if messages_number is None else int(messages_number)
        except Exception as e:
            self.helper.connector_logger.warning(
                "Failed to read the connector queue size",
                {"error": f"{type(e).__name__}: {e}"},
            )
            return None

    def is_stalled_work_released(self, entry, work_id, processed, expected):
        """
        Decide whether a work with no progress for WORK_STALL_TIMEOUT is waited for.

        Its messages may still be in the queue (workers down or far behind): releasing
        it would let newer files be sent while older versions still wait, the very
        race the wait prevents. The work is therefore released only once the queue is
        empty, which means its messages are gone (lost or dead-lettered). When the
        platform does not report the queue size, the timeout alone decides.
        """
        details = {
            "work_id": work_id,
            "progress_at": entry.get("progress_at"),
            "processed": processed,
            "expected": expected,
        }
        messages_number = self.get_queue_messages_number()
        if messages_number is None:
            self.helper.connector_logger.warning(
                "Work made no progress for too long and the queue size is unknown, "
                "not waiting for it anymore",
                details,
            )
            return True
        if messages_number > 0:
            self.helper.connector_logger.warning(
                "Work made no progress for too long but the queue still holds "
                "messages, waiting for them to be processed or reset the connector "
                "state to stop waiting",
                {**details, "queue_messages": messages_number},
            )
            return False
        self.helper.connector_logger.warning(
            "Work made no progress for too long and the queue is empty, its remaining "
            "messages are lost: not waiting for it anymore",
            details,
        )
        return True

    def has_pending_works(self):
        """
        Tell whether a work sent by a previous run is still being ingested.

        Workers apply the bundles of a queue in parallel: a version sent while an older
        one still waits in the queue can be applied first, and then overwritten. New
        files therefore stay in the bucket until the previous works are complete. The
        next run compares them with what the platform then holds.
        A work that makes no progress for WORK_STALL_TIMEOUT is released once the
        connector queue is empty (see `is_stalled_work_released`).
        """
        state = self.helper.get_state() or {}
        pending = state.get(PENDING_WORKS_STATE_KEY) or []
        if not pending:
            return False

        now = datetime.datetime.now(datetime.timezone.utc)
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
            stalled = False
            if processed != entry.get("processed") or not progress_at:
                entry["processed"] = processed
                entry["progress_at"] = now.isoformat()
            else:
                stalled = now - parse_stix_timestamp(progress_at) > WORK_STALL_TIMEOUT
            if stalled:
                if self.is_stalled_work_released(entry, work_id, processed, expected):
                    continue
            else:
                self.helper.connector_logger.info(
                    "Work of a previous run is still in progress",
                    {"work_id": work_id, "processed": processed, "expected": expected},
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
                "progress_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
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
            self.helper.connector_logger.info(
                "Waiting for the works of the previous run to complete before "
                "processing new files"
            )
            return

        files_by_prefix = {}
        for prefix in self.s3_bucket_prefixes:
            self.helper.connector_logger.info(
                "Listing files in S3 bucket",
                {"bucket": self.s3_bucket_name, "prefix": prefix},
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

        # Every bundle of the run is built before the first one is sent: a file that
        # cannot be processed stops the run before anything is sent or deleted
        for s3_file in run_files:
            s3_file["bundle"] = (
                self.fix_bundle(
                    s3_file["data"],
                    file_name=s3_file["key"],
                    original_content=s3_file["content"],
                )
                if isinstance(s3_file["data"], dict)
                else None
            )

        for prefix, files in files_by_prefix.items():
            if not files:
                continue

            # Work ID created lazily - only when we have valid content to send
            work_id = None
            processed_files = 0

            for s3_file in files:
                file_key = s3_file["key"]
                fixed_bundle = s3_file["bundle"]
                self.helper.connector_logger.info("Processing file", {"file": file_key})

                # Only process valid bundles (fix_bundle returns None or JSON string)
                if fixed_bundle is not None:
                    # Create work job only on first valid bundle (lazy initialization)
                    if work_id is None:
                        now = datetime.datetime.now(datetime.timezone.utc)
                        friendly_name = f"S3/{prefix} run @ " + now.isoformat()
                        # Multipart: the work completes once every bundle is processed
                        work_id = self.helper.api.work.initiate_work(
                            self.helper.connect_id, friendly_name, is_multipart=True
                        )
                        self.register_pending_work(work_id)

                    # Send bundle to OpenCTI
                    # If this fails, connector crashes - file is NOT deleted
                    self.helper.connector_logger.info(
                        "Sending STIX bundle from file", {"file": file_key}
                    )
                    self.helper.send_stix2_bundle(
                        bundle=fixed_bundle,
                        work_id=work_id,
                        no_split=self.s3_no_split_bundles,
                    )
                    processed_files += 1

                    # Optionally delete file from S3 after successful processing
                    if self.s3_delete_after_import:
                        self.helper.connector_logger.info(
                            "Deleting processed file", {"file": file_key}
                        )
                        self.s3_client.delete_object(
                            Bucket=self.s3_bucket_name, Key=file_key
                        )
                        self.helper.connector_logger.info(
                            "Successfully processed and deleted file",
                            {"file": file_key},
                        )
                    else:
                        self.helper.connector_logger.info(
                            "Successfully processed file (kept in bucket for debug)",
                            {"file": file_key},
                        )
                else:
                    # Empty/invalid bundle - optionally delete the file
                    if self.s3_delete_after_import:
                        self.helper.connector_logger.warning(
                            "File has no valid STIX content, deleting",
                            {"file": file_key},
                        )
                        self.s3_client.delete_object(
                            Bucket=self.s3_bucket_name, Key=file_key
                        )
                    else:
                        self.helper.connector_logger.warning(
                            "File has no valid STIX content (kept in bucket for debug)",
                            {"file": file_key},
                        )

            # Only finalize work if we actually processed something
            if work_id is not None:
                message = (
                    f"Connector successfully processed S3 prefix '{prefix}': "
                    f"{processed_files} file(s) ingested"
                )
                self.helper.connector_logger.info(
                    "Connector successfully processed S3 prefix",
                    {"prefix": prefix, "files": processed_files},
                )
                self.helper.api.work.to_processed(work_id, message)
            else:
                self.helper.connector_logger.info(
                    "No valid STIX content found in S3 prefix", {"prefix": prefix}
                )

    def run(self):
        self.helper.connector_logger.info(
            "Starting S3 connector", {"interval_seconds": self.get_interval()}
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
