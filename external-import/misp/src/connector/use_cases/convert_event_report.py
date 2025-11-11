import re
from datetime import datetime, timezone

import pycti
import stix2
import stix2.exceptions
from api_client.models import EventReportItem

from .common import ConverterConfig, ConverterError
from .utils import find_type_by_uuid


class EventReportConverterError(ConverterError):
    """Custom exception for event's reports conversion errors."""


class EventReportConverter:
    def __init__(self, config: ConverterConfig):
        self.config = config

    def format_note_content(self, content, bundle_objects):
        # Markdown object, attribute & tag links should be converted from MISP links to OpenCTI links
        def reformat(match):
            type = match.group(1)
            uuid = match.group(2)
            result = find_type_by_uuid(uuid, bundle_objects)
            if result is None:
                return "[{}:{}](/dashboard/search/{})".format(type, uuid, uuid)
            if result["type"] == "indicator":
                name = result["entity"]["pattern"]
            else:
                name = result["entity"]["value"]
            return "[{}:{}](/dashboard/search/{})".format(
                type, name, result["entity"]["id"]
            )

        r_object = r"@\[(object|attribute)\]\(([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\)"
        r_tag = r'@\[tag\]\(([a-zA-Z:"\'0-9\-=]+)\)'

        content = re.sub(r_object, reformat, content, flags=re.MULTILINE)
        content = re.sub(r_tag, r"tag:\1", content, flags=re.MULTILINE)
        return content

    def create_note(
        self,
        event_report: EventReportItem,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
        object_refs: list[stix2.v21._STIXBase21],
        bundle_objects: list[stix2.v21._STIXBase21],
    ) -> stix2.Note | None:
        content = self.format_note_content(event_report.content, bundle_objects)
        created_at = datetime.fromtimestamp(
            int(event_report.timestamp), tz=timezone.utc
        )

        return stix2.Note(
            id=pycti.Note.generate_id(created=created_at, content=content),
            created=created_at,
            modified=created_at,
            created_by_ref=author["id"],
            object_marking_refs=markings,
            abstract=event_report.name,
            content=content,
            object_refs=object_refs,
            allow_custom=True,
        )

    def process(
        self,
        event_report: EventReportItem,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
        object_refs: list[stix2.v21.Report],
        bundle_objects: list[stix2.v21._STIXBase21],
    ) -> list[stix2.v21._STIXBase21]:
        stix_objects = []

        try:
            note = self.create_note(
                event_report,
                author=author,
                markings=markings,
                object_refs=object_refs,
                bundle_objects=bundle_objects,
            )
            if note:
                stix_objects.append(note)
        except stix2.exceptions.STIXError as err:
            raise EventReportConverterError(
                "Error while converting event's report"
            ) from err

        return stix_objects
