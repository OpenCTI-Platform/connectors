"""Stream connector deriving Intrusion Sets from Malanta ``apt:`` labels."""

import json
from typing import Any

from connector.converter_to_stix import ConverterToStix
from connector.labels import extract_label_values, parse_actor_labels
from connector.settings import ConnectorSettings
from pycti import Identity, OpenCTIConnectorHelper

INDICATOR_TYPE = "indicator"
HANDLED_EVENTS = ("create", "update")


class MalantaAttributionConnector:
    """Turns Malanta's flat attribution labels into a usable attribution graph.

    Malanta's TAXII feed is ingested by OpenCTI's built-in TAXII ingester, which
    applies no transformation. Attribution therefore arrives as flat label
    strings on Indicators (``apt:APT44``) rather than as entities. This connector
    listens to the platform's event stream and, for each such Indicator *authored by
    the configured source*, creates the matching Intrusion Set and an ``indicates``
    relationship. Indicators from other feeds are skipped, so a second source using
    the same ``apt:`` convention is never attributed to Malanta.

    It deliberately does **not** touch Malanta's own infrastructure clusters. An
    ``apt:`` label on an Indicator pointing at a cluster does not make the
    cluster that actor -- a cluster may aggregate infrastructure from several
    actors -- so attribution is applied to Indicators only.

    Because the connector emits only Intrusion Sets and relationships, and never
    modifies the Indicator it reacts to, the objects it writes cannot re-trigger
    it. Any future change that writes back to the Indicator itself must exclude
    self-authored events explicitly, or the connector will loop.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        :param config: Connector configuration.
        :param helper: Helper managing the connection to OpenCTI.
        """
        self.config = config
        self.helper = helper
        self.converter_to_stix = ConverterToStix(
            author_name=config.malanta_attribution.author_name,
            author_description=config.malanta_attribution.author_description,
        )
        # Provenance guard. OpenCTI normalises an identity's STIX id to a
        # deterministic value derived from its name, and the event stream carries
        # that normalised id -- not whatever id the upstream feed used. Computing
        # the same id here lets us match an indicator's author without resolving
        # anything against the API.
        source_author = config.malanta_attribution.source_author
        self.expected_author_ref = (
            Identity.generate_id(source_author, "organization")
            if source_author
            else None
        )

    def check_stream_id(self) -> None:
        """Validate that a live stream is configured.

        :raises ValueError: If the stream id is missing or left at its placeholder.
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def process_message(self, msg: Any) -> None:
        """Handle one event from the live stream.

        Events that are not Indicator creations or updates are ignored, as are
        Indicators without attribution labels -- the large majority, since only
        a small share of the feed carries ``apt:`` tokens.

        :param msg: Message event from the stream.
        """
        try:
            self.check_stream_id()
            data = json.loads(msg.data)["data"]
        except Exception as err:
            self.helper.connector_logger.error(
                "[STREAM] Cannot process the message", {"error": str(err)}
            )
            return

        if msg.event not in HANDLED_EVENTS:
            return
        if data.get("type") != INDICATOR_TYPE:
            return

        try:
            self._process_indicator(data)
        except Exception as err:
            # An unexpected failure on one event must not stop the stream.
            self.helper.connector_logger.error(
                "[STREAM] Failed to process indicator",
                {"indicator_id": data.get("id"), "error": str(err)},
            )

    def _process_indicator(self, indicator: dict[str, Any]) -> None:
        """Derive and send the attribution implied by one Indicator.

        :param indicator: The Indicator payload from the stream event.
        """
        settings = self.config.malanta_attribution
        indicator_id = indicator.get("id")

        if not self._is_expected_source(indicator):
            self.helper.connector_logger.debug(
                "[STREAM] Skipping indicator from another source",
                {
                    "indicator_id": indicator_id,
                    "created_by_ref": indicator.get("created_by_ref"),
                    "expected": self.expected_author_ref,
                },
            )
            return

        confidence = indicator.get("confidence")
        if (
            settings.min_confidence
            and confidence is not None
            and confidence < settings.min_confidence
        ):
            self.helper.connector_logger.debug(
                "[STREAM] Skipping indicator below confidence threshold",
                {"indicator_id": indicator_id, "confidence": confidence},
            )
            return

        actors = parse_actor_labels(
            extract_label_values(indicator),
            prefix=settings.label_prefix,
            separators=settings.actor_separators,
        )
        if not actors:
            self.helper.connector_logger.debug(
                "[STREAM] Indicator carries no attribution labels",
                {"indicator_id": indicator_id},
            )
            return

        stix_objects = self.converter_to_stix.build_attribution_objects(
            indicator=indicator,
            actors=actors,
            create_intrusion_sets=settings.create_intrusion_sets,
        )
        if not stix_objects:
            return

        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(bundle)

        self.helper.connector_logger.info(
            "[STREAM] Attribution created",
            {"indicator_id": indicator_id, "actors": actors},
        )

    def _is_expected_source(self, indicator: dict[str, Any]) -> bool:
        """Check the indicator came from the configured source.

        Several feeds may share a platform, and `apt:` is a plausible label
        namespace for any of them. Without this check the connector would derive
        Intrusion Sets from another vendor's labels and credit them to Malanta.

        :param indicator: The Indicator payload from the stream event.
        :return: True when the indicator should be processed.
        """
        if self.expected_author_ref is None:
            return True  # provenance filtering disabled
        return indicator.get("created_by_ref") == self.expected_author_ref

    def run(self) -> None:
        """Listen to the live stream until the process is stopped."""
        self.helper.listen_stream(message_callback=self.process_message)
