import json
import uuid
from datetime import datetime

from feedly.api_client.enterprise.indicators_of_compromise import StixIoCDownloader
from feedly.api_client.session import FeedlySession
from markdownify import markdownify
from pycti import OpenCTIConnectorHelper


class FeedlyConnector:
    def __init__(self, feedly_api_key: str, cti_helper: OpenCTIConnectorHelper):
        self.feedly_session = FeedlySession(feedly_api_key, client_name="feedly.opencti.client")
        self.cti_helper = cti_helper

    def fetch_and_publish(self, stream_id: str, newer_than) -> None:
        bundle = self.fetch_bundle(stream_id, newer_than)
        self.cti_helper.send_stix2_bundle(bundle)

    def fetch_bundle(self, stream_id: str, newer_than: datetime) -> str:
        bundle = StixIoCDownloader(self.feedly_session, newer_than, stream_id).download_all()
        _replace_html_description_with_md_note(bundle)
        self.cti_helper.log_info(f"Found {_count_reports(bundle)} new reports")
        return json.dumps(bundle)


def _count_reports(bundle: dict) -> int:
    return sum(1 for o in bundle["objects"] if o["type"] == "report")


def _replace_html_description_with_md_note(bundle: dict) -> None:
    notes = []
    for o in bundle["objects"]:
        if o["type"] == "report":
            notes.append(
                {
                    "type": "note",
                    "id": f"note--{uuid.uuid4()}",
                    "content": markdownify(o["description"]),
                    "object_refs": [o["id"]],
                }
            )
            o["description"] = ""
    bundle["objects"].extend(notes)
