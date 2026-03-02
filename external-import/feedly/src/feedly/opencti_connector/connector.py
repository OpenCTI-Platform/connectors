import json
import re
from datetime import datetime
from typing import Optional, cast

from feedly.api_client.enterprise.indicators_of_compromise import StixIoCDownloader
from feedly.api_client.session import FeedlySession
from markdown import markdown
from pycti import Identity, OpenCTIConnectorHelper, OpenCTIStix2Utils
from stix2 import NetworkTraffic

FEEDLY_AI_UUID = "identity--477866fd-8784-46f9-ab40-5592ed4eddd7"

# Pattern for IPv4 address followed by colon and port number
_IPV4_WITH_PORT = re.compile(r"^(?P<addr>\b(?:\d{1,3}\.){3}\d{1,3}\b):(?P<port>\d+)$")


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
        bundle = self.fetch_bundle(stream_id, newer_than)
        if not bundle["objects"]:
            return
        self.cti_helper.send_stix2_bundle(json.dumps(bundle))
        return self._get_last_article_published_date(bundle)

    def fetch_bundle(self, stream_id: str, newer_than: datetime) -> dict:
        bundle = StixIoCDownloader(
            session=self.feedly_session,
            newer_than=newer_than,
            older_than=None,
            stream_id=stream_id,
        ).download_all()

        bundle = cast("dict", bundle)
        self._make_reports_content_instead_of_descriptions(bundle)
        self._add_main_observable_type_to_indicators(bundle)
        self._transform_threat_actors_to_intrusion_sets(bundle)
        self._add_source_name_as_author_to_all_reports(bundle)
        self._fix_ip_addresses_with_ports(bundle)

        if not self.enable_relationships:
            self._filter_relationships(bundle)

        self.cti_helper.log_info(f"Found {self._count_reports(bundle)} new reports")
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

    @staticmethod
    def _make_reports_content_instead_of_descriptions(bundle: dict) -> None:
        notes = []
        for o in bundle["objects"]:
            if o["type"] == "report":
                o["content"], o["description"] = (
                    markdown(o["description"]),
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
