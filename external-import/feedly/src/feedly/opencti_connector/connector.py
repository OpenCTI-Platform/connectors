import json
import re
from datetime import datetime
from typing import Optional

from feedly.api_client.enterprise.indicators_of_compromise import StixIoCDownloader
from feedly.api_client.session import FeedlySession
from markdown import markdown
from pycti import Identity, OpenCTIConnectorHelper, OpenCTIStix2Utils
from stix2 import NetworkTraffic

FEEDLY_AI_UUID = "identity--477866fd-8784-46f9-ab40-5592ed4eddd7"

# Pattern for IPv4 address followed by colon and port number
_IPV4_WITH_PORT = re.compile(r"^(?P<addr>\b(?:\d{1,3}\.){3}\d{1,3}\b):(?P<port>\d+)$")

# Guardrail for converting report descriptions to Markdown. Descriptions come from
# arbitrary external Feedly articles; a long run of the same Markdown-active symbol
# (e.g. backticks or brackets) triggers catastrophic regex backtracking in the parser,
# pinning the CPU for minutes with no progress and no logs. We defuse that by shortening
# only such degenerate symbol runs -- no report text is ever truncated, so nothing is
# lost. Runs of letters/digits (e.g. base64, hashes) are not Markdown-active and are
# left untouched.
_MARKDOWN_MAX_CHAR_RUN = 50
_MARKDOWN_LONG_RUN = re.compile(r"([^\w\s])\1{%d,}" % _MARKDOWN_MAX_CHAR_RUN)


def _sanitize_markdown_input(text: str) -> str:
    """Make untrusted text safe to feed to python-markdown without losing content.

    Collapses runs of the same Markdown-active symbol longer than
    ``_MARKDOWN_MAX_CHAR_RUN`` so that pathological article content cannot trigger
    catastrophic regex backtracking in the Markdown parser (which would otherwise hang
    the connector at 100% CPU with no logs). Only degenerate symbol runs are shortened;
    letters, digits and normal text are left untouched and nothing is truncated.
    """
    if not isinstance(text, str) or not text:
        return text
    return _MARKDOWN_LONG_RUN.sub(
        lambda match: match.group(1) * _MARKDOWN_MAX_CHAR_RUN, text
    )


class FeedlyConnector:
    def __init__(
        self,
        feedly_api_key: str,
        cti_helper: OpenCTIConnectorHelper,
        enable_relationships: bool = True,
    ):
        self.feedly_session = FeedlySession(
            feedly_api_key, client_name="feedly.opencti.client"
        )
        self.cti_helper = cti_helper
        self.enable_relationships = enable_relationships

    def fetch_and_publish(self, stream_id: str, newer_than: datetime) -> Optional[str]:
        last_article_published_date = None
        total_reports = 0

        self.cti_helper.log_debug(
            "Initializing Feedly downloader",
            meta={"stream_id": stream_id, "newer_than": newer_than.isoformat()},
        )
        downloader = StixIoCDownloader(
            session=self.feedly_session,
            newer_than=newer_than,
            older_than=None,
            stream_id=stream_id,
        )

        batch_index = 0
        for batch in downloader.stream_bundles():
            batch_index += 1
            # Logged only *after* the (blocking) HTTP fetch returns: if Feedly stalls,
            # the previous log line is the last one seen -> points at the network wait.
            self.cti_helper.log_debug(
                "Received Feedly batch",
                meta={
                    "stream_id": stream_id,
                    "batch": batch_index,
                    "objects": len(batch.get("objects", [])),
                },
            )
            bundle = self._process_bundle(batch)
            if not bundle["objects"]:
                self.cti_helper.log_debug(
                    "Skipping empty batch after processing",
                    meta={"stream_id": stream_id, "batch": batch_index},
                )
                continue
            total_reports += self._count_reports(bundle)
            # Logged before the (blocking) send: if serialization/splitting or the
            # broker stalls, this is the last line seen -> points at the publish step.
            self.cti_helper.log_debug(
                "Sending STIX bundle to OpenCTI",
                meta={
                    "stream_id": stream_id,
                    "batch": batch_index,
                    "objects": len(bundle["objects"]),
                },
            )
            self.cti_helper.send_stix2_bundle(json.dumps(bundle))
            self.cti_helper.log_debug(
                "STIX bundle accepted by OpenCTI",
                meta={"stream_id": stream_id, "batch": batch_index},
            )
            batch_last_date = self._get_last_article_published_date(bundle)
            if batch_last_date:
                if (
                    last_article_published_date is None
                    or batch_last_date > last_article_published_date
                ):
                    last_article_published_date = batch_last_date

        self.cti_helper.log_debug(
            "Feedly stream fully consumed",
            meta={
                "stream_id": stream_id,
                "batches": batch_index,
                "reports": total_reports,
            },
        )
        self.cti_helper.log_info(f"Found {total_reports} new reports")
        return last_article_published_date

    def _process_bundle(self, bundle: dict) -> dict:
        object_count = len(bundle["objects"])
        self.cti_helper.log_debug(
            "Converting report descriptions to markdown",
            meta={"objects": object_count},
        )
        self._make_reports_content_instead_of_descriptions(bundle)
        self.cti_helper.log_debug("Adding main observable types to indicators")
        self._add_main_observable_type_to_indicators(bundle)
        self.cti_helper.log_debug("Transforming threat actors to intrusion sets")
        self._transform_threat_actors_to_intrusion_sets(bundle)
        self.cti_helper.log_debug("Adding source names as authors")
        self._add_source_name_as_author_to_all_reports(bundle)
        self.cti_helper.log_debug("Fixing IP addresses with ports")
        self._fix_ip_addresses_with_ports(bundle)

        if not self.enable_relationships:
            self.cti_helper.log_debug("Filtering out relationships")
            self._filter_relationships(bundle)

        return bundle

    @staticmethod
    def _filter_relationships(bundle: dict) -> None:
        removed_ids = {
            o["id"] for o in bundle["objects"] if o["type"] == "relationship"
        }
        bundle["objects"] = [
            o for o in bundle["objects"] if o["type"] != "relationship"
        ]
        for o in bundle["objects"]:
            if "object_refs" in o:
                o["object_refs"] = [
                    ref for ref in o["object_refs"] if ref not in removed_ids
                ]

    @staticmethod
    def _count_reports(bundle: dict) -> int:
        return sum(1 for o in bundle["objects"] if o["type"] == "report")

    @staticmethod
    def _fix_ip_addresses_with_ports(bundle: dict) -> None:
        new_objects = []

        for o in bundle["objects"]:
            if o["type"] != "ipv4-addr":
                continue

            old_ip_value = o["value"]
            if not (match := _IPV4_WITH_PORT.match(old_ip_value)):
                continue

            o["value"] = match["addr"]
            tlp_marking = o.get("object_marking_refs", [])
            nt = NetworkTraffic(
                dst_ref=o["id"],
                dst_port=int(match["port"]),
                protocols=["tcp"],
                object_marking_refs=tlp_marking,
            )
            new_objects.append(json.loads(nt.serialize()))

        if new_objects:
            bundle["objects"].extend(new_objects)

    def _make_reports_content_instead_of_descriptions(self, bundle: dict) -> None:
        notes = []
        for o in bundle["objects"]:
            if o["type"] == "report":
                description = o["description"]
                sanitized = _sanitize_markdown_input(description)
                if isinstance(description, str) and sanitized != description:
                    # The guard only alters pathological content (huge input or long
                    # runs of Markdown-active characters) that would otherwise hang the
                    # Markdown parser. Surface it so such reports can be spotted.
                    self.cti_helper.log_warning(
                        "Report description sanitized before markdown conversion",
                        meta={
                            "report_id": o.get("id"),
                            "original_length": len(description),
                            "sanitized_length": len(sanitized),
                        },
                    )
                self.cti_helper.log_debug(
                    "Converting report description to markdown",
                    meta={
                        "report_id": o.get("id"),
                        "description_length": (
                            len(description) if isinstance(description, str) else 0
                        ),
                    },
                )
                o["content"], o["description"] = (
                    markdown(sanitized),
                    o["name"],
                )
        bundle["objects"].extend([json.loads(note.serialize()) for note in notes])

    @staticmethod
    def _add_main_observable_type_to_indicators(bundle: dict) -> None:
        for o in bundle["objects"]:
            if o["type"] == "indicator" and "pattern" in o:
                pattern = o["pattern"]
                stix_type = pattern.removeprefix("[").split(":")[0].strip()
                o["x_opencti_main_observable_type"] = (
                    OpenCTIStix2Utils.stix_observable_opencti_type(stix_type)
                )

    def _transform_threat_actors_to_intrusion_sets(self, bundle: dict) -> None:
        for o in bundle["objects"]:
            if o["type"] == "threat-actor":
                o["type"] = "intrusion-set"
                o["id"] = o.get("id").replace("threat-actor", "intrusion-set")
            if self.enable_relationships and o["type"] == "relationship":
                o["source_ref"] = o.get("source_ref").replace(
                    "threat-actor", "intrusion-set"
                )
                o["target_ref"] = o.get("target_ref").replace(
                    "threat-actor", "intrusion-set"
                )
                if o["relationship_type"] == "located-at" and (
                    o["source_ref"].startswith("intrusion-set")
                    or o["target_ref"].startswith("intrusion-set")
                ):
                    o["relationship_type"] = "originates-from"
            for i, object_ref in enumerate(o.get("object_refs", [])):
                o["object_refs"][i] = object_ref.replace(
                    "threat-actor", "intrusion-set"
                )

    def _add_source_name_as_author_to_all_reports(self, bundle: dict) -> None:
        source_identity_objects = []
        for o in bundle["objects"]:
            if o["type"] == "report":
                source_identity_object = self._add_source_name_as_author_to_report(o)
                if source_identity_object:
                    source_identity_objects.append(source_identity_object)
        bundle["objects"].extend(source_identity_objects)

    def _add_source_name_as_author_to_report(self, report: dict) -> Optional[dict]:
        if len(report["external_references"]) < 2:
            return
        source_name = report["external_references"][1].get("source_name")
        report["created_by_ref"] = self._make_source_id(source_name)
        return self._make_source_identity_object(source_name)

    @staticmethod
    def _make_source_identity_object(source_name: str) -> dict:
        return {
            "type": "identity",
            "name": source_name,
            "identity_class": "organization",
            "id": Identity.generate_id(name=source_name, identity_class="organization"),
        }

    @staticmethod
    def _make_source_id(source_name: str) -> str:
        return Identity.generate_id(name=source_name, identity_class="organization")

    @staticmethod
    def _get_last_article_published_date(bundle: dict) -> Optional[str]:
        return max(
            (o["published"] for o in bundle["objects"] if o["type"] == "report"),
            default=None,
        )
