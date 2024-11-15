import json
from datetime import datetime
from typing import Optional
from uuid import NAMESPACE_DNS, uuid5

from feedly.api_client.enterprise.indicators_of_compromise import StixIoCDownloader
from feedly.api_client.session import FeedlySession
from markdown import markdown
from pycti import OpenCTIConnectorHelper, OpenCTIStix2Utils

FEEDLY_AI_UUID = "identity--477866fd-8784-46f9-ab40-5592ed4eddd7"


class FeedlyConnector:
    def __init__(self, feedly_api_key: str, cti_helper: OpenCTIConnectorHelper):
        self.feedly_session = FeedlySession(
            feedly_api_key, client_name="feedly.opencti.client"
        )
        self.cti_helper = cti_helper

    def fetch_and_publish(self, stream_id: str, newer_than: datetime) -> Optional[str]:
        bundle = self.fetch_bundle(stream_id, newer_than)
        if not bundle["objects"]:
            return
        self.cti_helper.send_stix2_bundle(json.dumps(bundle))
        return _get_last_article_published_date(bundle)

    def fetch_bundle(self, stream_id: str, newer_than: datetime) -> dict:
        bundle = StixIoCDownloader(
            self.feedly_session, newer_than, stream_id
        ).download_all()
        _make_reports_content_instead_of_descriptions(bundle)
        _add_main_observable_type_to_indicators(bundle)
        _transform_threat_actors_to_intrusion_sets(bundle)
        _add_source_name_as_author_to_all_reports(bundle)
        self.cti_helper.log_info(f"Found {_count_reports(bundle)} new reports")
        return bundle


def _count_reports(bundle: dict) -> int:
    return sum(1 for o in bundle["objects"] if o["type"] == "report")


def _make_reports_content_instead_of_descriptions(bundle: dict) -> None:
    notes = []
    for o in bundle["objects"]:
        if o["type"] == "report":
            o["content"], o["description"] = (
                markdown(o["description"]),
                o["name"],
            )
    bundle["objects"].extend([json.loads(note.serialize()) for note in notes])


def _add_main_observable_type_to_indicators(bundle: dict) -> None:
    for o in bundle["objects"]:
        if o["type"] == "indicator" and "pattern" in o:
            pattern = o["pattern"]
            stix_type = pattern.removeprefix("[").split(":")[0].strip()
            o["x_opencti_main_observable_type"] = (
                OpenCTIStix2Utils.stix_observable_opencti_type(stix_type)
            )


def _transform_threat_actors_to_intrusion_sets(bundle: dict) -> None:
    for o in bundle["objects"]:
        if o["type"] == "threat-actor":
            o["type"] = "intrusion-set"
            o["id"] = o.get("id").replace("threat-actor", "intrusion-set")
        if o["type"] == "relationship":
            o["source_ref"] = o.get("source_ref").replace(
                "threat-actor", "intrusion-set"
            )
            o["target_ref"] = o.get("target_ref").replace(
                "threat-actor", "intrusion-set"
            )


def _add_source_name_as_author_to_all_reports(bundle: dict) -> None:
    source_identity_objects = []
    for o in bundle["objects"]:
        if o["type"] == "report":
            source_identity_object = _add_source_name_as_author_to_report(o)
            if source_identity_object:
                source_identity_objects.append(source_identity_object)
    bundle["objects"].extend(source_identity_objects)


def _add_source_name_as_author_to_report(report: dict) -> Optional[dict]:
    if len(report["external_references"]) < 2:
        return
    source_name = report["external_references"][1].get("source_name")
    report["created_by_ref"] = _make_source_id(source_name)
    return _make_source_identity_object(source_name)


def _make_source_identity_object(source_name: str) -> dict:
    return {
        "type": "identity",
        "name": source_name,
        "identity_class": "organization",
        "id": _make_source_id(source_name),
    }


def _make_source_id(source_name: str) -> str:
    return f"identity--{uuid5(NAMESPACE_DNS, 'feedly:source:'+source_name)}"


def _get_last_article_published_date(bundle: dict) -> Optional[str]:
    return max(
        (o["published"] for o in bundle["objects"] if o["type"] == "report"),
        default=None,
    )
