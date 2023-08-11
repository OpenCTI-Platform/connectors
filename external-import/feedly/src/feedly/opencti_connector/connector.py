import json
from datetime import datetime

from feedly.api_client.enterprise.indicators_of_compromise import StixIoCDownloader
from feedly.api_client.session import FeedlySession
from pycti import OpenCTIConnectorHelper
from stix2 import Note

FEEDLY_AI_UUID = "identity--477866fd-8784-46f9-ab40-5592ed4eddd7"


class FeedlyConnector:
    def __init__(self, feedly_api_key: str, cti_helper: OpenCTIConnectorHelper):
        self.feedly_session = FeedlySession(
            feedly_api_key, client_name="feedly.opencti.client"
        )
        self.cti_helper = cti_helper

    def fetch_and_publish(self, stream_id: str, newer_than) -> None:
        bundle = self.fetch_bundle(stream_id, newer_than)
        if not bundle["objects"]:
            return
        self.cti_helper.send_stix2_bundle(json.dumps(bundle))

    def fetch_bundle(self, stream_id: str, newer_than: datetime) -> dict:
        bundle = StixIoCDownloader(
            self.feedly_session, newer_than, stream_id
        ).download_all()
        _replace_description_with_note(bundle)
        self.cti_helper.log_info(f"Found {_count_reports(bundle)} new reports")
        return bundle


def _count_reports(bundle: dict) -> int:
    return sum(1 for o in bundle["objects"] if o["type"] == "report")


def _replace_description_with_note(bundle: dict) -> None:
    notes = []
    for o in bundle["objects"]:
        if o["type"] == "report":
            notes.append(
                Note(
                    content=o["description"],
                    object_refs=[o["id"]],
                    created_by_ref=FEEDLY_AI_UUID,
                )
            )
            o["description"] = ""
    bundle["objects"].extend([json.loads(note.serialize()) for note in notes])
