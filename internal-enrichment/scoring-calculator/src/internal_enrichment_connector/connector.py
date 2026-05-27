from typing import Optional, Tuple

from pycti import OpenCTIApiClient, OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_loader import ConfigConnector


def _coerce_score(value, default: int = 0) -> int:
    """Coerce an ``x_opencti_score`` payload into a clamped 0..100 ``int``.

    OpenCTI treats ``x_opencti_score`` as optional on indicators; a stored
    value can legitimately be ``None`` (key present, no score), a numeric
    string (``"42"`` from a STIX-1 / legacy import), a float, or even
    garbage from an upstream connector that wrote the wrong type.
    ``dict.get(key, default)`` returns the actual stored value when the
    key exists with ``None``, so the bare ``int(entity.get("x_opencti_score", 0))``
    shape crashes the enrichment with ``TypeError`` (``int(None)``) or
    ``ValueError`` (``int("foo")``). Coerce defensively, fall back to
    ``default`` on any failure, and clamp to the platform's documented
    0..100 range so a malformed upstream value can never push a downstream
    update outside the valid range.
    """
    if value is None:
        return default
    try:
        coerced = int(float(value))
    except (TypeError, ValueError):
        return default
    return max(0, min(100, coerced))


THREAT_ENTITIES = [
    "Intrusion-Set",
    "Threat-Actor",
    "Threat-Actor-Individual",
    "Threat-Actor-Group",
]
TOOLBOX_ENTITIES = ["Malware", "Tool"]
LOCATION_ENTITIES = ["Country", "Region"]
SECTOR_ENTITIES = ["Sector"]
TTP_ENTITIES = ["Attack-Pattern"]
AUTHOR_ENTITIES = ["Organization", "Individual"]


def _category_of(entity_type):
    if entity_type in THREAT_ENTITIES:
        return "Threat"
    elif entity_type in TOOLBOX_ENTITIES:
        return "Toolbox"
    elif entity_type in LOCATION_ENTITIES:
        return "Location"
    elif entity_type in SECTOR_ENTITIES:
        return "Sector"
    elif entity_type in TTP_ENTITIES:
        return "TTP"
    elif entity_type in AUTHOR_ENTITIES:
        return "Author"
    return None


class ConnectorScoring:
    """
    Specifications of the internal enrichment connector

    This class encapsulates the main actions, expected to be run by any internal enrichment connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to enrich a data (Observables) created or modified in the OpenCTI core platform.
    It will create a STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    Ingesting a bundle allow the connector to be compatible with the playbook automation feature.


    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ

    """

    def __init__(
        self,
        config: ConfigConnector,
        helper: OpenCTIConnectorHelper,
        api: OpenCTIApiClient,
    ):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.client = ConnectorClient(api)

    # In case labels of two different priorities are present, keep the highest priority
    def _priority_of(self, entity):
        # Defensive ``.get(...) or []`` rather than ``entity["objectLabel"]``:
        # the GraphQL query always requests ``objectLabel``, but a partially
        # populated payload (e.g. a future schema change, a non-StixDomainObject
        # node slipping through the inline fragment, or a future caller that
        # forgets to fetch labels) would otherwise crash the entire enrichment
        # via ``KeyError`` / ``TypeError`` before the scope check could
        # short-circuit. Same reasoning for ``label.get("value", "")``.
        priority = []
        for label in entity.get("objectLabel") or []:
            label_value = (label.get("value") or "").lower()
            if not label_value:
                continue
            if label_value in self.config.high_priority_labels:
                return "high"
            elif label_value in self.config.medium_priority_labels:
                priority.append("medium")
            elif label_value in self.config.low_priority_labels:
                priority.append("low")

        if "medium" in priority:
            return "medium"
        elif "low" in priority:
            return "low"

        return None

    def _impact_on_score(self, entity) -> int:
        entity_type = entity.get("entity_type", "")
        category = _category_of(entity_type)
        if not category:
            return 0

        enabled = self.config.impact_enabled.get(category, False)
        self.helper.connector_logger.debug(
            "Impact configuration evaluated",
            meta={"category": category, "enabled": enabled},
        )
        if not enabled:
            return 0

        prio = self._priority_of(entity)
        if not prio:
            return 0

        impact = self.config.impact_map.get(category, {}).get(prio, 0)
        return impact

    def _compute_score(
        self, entity_to_enrich, indicator_context, indicator_author
    ) -> dict:
        """Apply the aggregated per-category impact to the indicator's score.

        Mutates ``entity_to_enrich["x_opencti_score"]`` in place using
        the relative-percentage formula documented in the README and
        returns the same dict so the caller can wrap it in a STIX
        bundle. The previous ``-> list`` annotation + ``"List of STIX
        objects"`` docstring described a return shape this method
        never actually produced.
        """

        self.helper.connector_logger.debug(
            "Start compute the impact on score",
            meta={
                "indicator_id": entity_to_enrich.get("id"),
                "current_score": entity_to_enrich.get("x_opencti_score"),
                "context_size": len(indicator_context),
                "author_present": bool(indicator_author),
            },
        )

        total_impact = 0
        for entity in indicator_context:
            impact = self._impact_on_score(entity)
            total_impact += impact
            self.helper.connector_logger.debug(
                "Relation impact on score",
                meta={
                    "entity_id": entity.get("id"),
                    "entity_type": entity.get("entity_type"),
                    "impact": impact,
                },
            )

        if indicator_author:
            impact = self._impact_on_score(indicator_author)
            total_impact += impact
            self.helper.connector_logger.debug(
                "Author impact on score",
                meta={
                    "entity_id": indicator_author.get("id"),
                    "entity_type": indicator_author.get("entity_type"),
                    "impact": impact,
                },
            )

        # Clamp on both sides: the connector's contract is forward-only
        # (never reduces a score), so a misconfigured negative
        # per-priority value would otherwise pull the score *down* via
        # the relative-percentage formula. ``max(0.0, ...)`` upholds
        # the contract regardless of how the operator configured the
        # impact map.
        impact_ratio = max(0.0, min(1.0, total_impact / 100))

        # ``_coerce_score`` handles every edge case the bare
        # ``int(entity.get("x_opencti_score", 0))`` would crash on:
        # ``None`` (key present with no value), numeric strings, floats,
        # and out-of-range upstream garbage. Pre-existing scores outside
        # 0..100 are clamped before the formula runs so the resulting
        # ``new_score`` is always a valid OpenCTI score.
        actual_score = _coerce_score(entity_to_enrich.get("x_opencti_score"))
        new_score = actual_score + ((100 - actual_score) * impact_ratio)

        entity_to_enrich["x_opencti_score"] = _coerce_score(round(new_score))

        self.helper.connector_logger.debug(
            "Score computation result",
            meta={
                "total_impact": total_impact,
                "impact_ratio": impact_ratio,
                "old_score": actual_score,
                "new_score": entity_to_enrich["x_opencti_score"],
            },
        )

        return entity_to_enrich

    def entity_in_scope(self, data) -> Tuple[bool, Optional[str]]:
        """Decide whether the incoming entity should be enriched.

        Returns a ``(in_scope, reason)`` tuple. ``reason`` is ``None``
        on the happy path and a human-readable status string when
        ``in_scope`` is ``False`` — the caller surfaces that reason
        verbatim to the worker queue so the operator can tell an
        entity-type-scope mismatch (e.g. a ``Report`` accidentally
        routed to an Indicator connector) apart from an
        observable-type-not-enrichable rejection (e.g. an ``Email-Addr``
        Indicator while the connector is configured for IPs / domains
        / files). The previous bare-``bool`` shape forced the caller
        to assume one specific reason for the rejection and produced
        misleading status strings like ``"... None is not in
        indicator_type_enrichable"`` on the entity-type-scope path.
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = data["entity_id"].split("--")
        entity_type = entity_split[0].lower()
        entity = data["stix_entity"]

        # Use ``.get(...)`` (not bracket indexing / unconditional string
        # concat) so the debug log can never crash on a non-Indicator
        # entity that ends up routed here — ``pattern_type`` and
        # ``x_opencti_main_observable_type`` are Indicator-specific
        # attributes and would otherwise raise ``TypeError`` when the
        # ``+`` operator hit a ``None`` value. Move the context to
        # structured ``meta=`` so it is queryable rather than buried
        # in a string.
        self.helper.connector_logger.debug(
            "Evaluating object support",
            meta={
                "pattern_type": entity.get("pattern_type"),
                "observable_type": entity.get("x_opencti_main_observable_type"),
                "enrichable_types": self.config.indicator_type_enrichable,
            },
        )

        if entity_type not in scopes:
            reason = (
                f"Object not enriched, entity type {entity_type!r} "
                f"is not in the connector scope"
            )
            self.helper.connector_logger.info(
                reason,
                meta={"entity_type": entity_type, "scopes": scopes},
            )
            return False, reason

        pattern_type = entity.get("pattern_type")
        ioc_type = entity.get("x_opencti_main_observable_type")

        # Distinguish the two rejection causes so the operator-facing
        # status string reflects the real reason. The previous shape
        # collapsed both checks into a single ``observable type ... is
        # not in indicator_type_enrichable`` reason, which was misleading
        # for non-STIX indicators (e.g. YARA / Sigma / SNORT) — those
        # would surface as ``observable type None ...`` even though the
        # actual blocker was the ``pattern_type``.
        if pattern_type != "stix":
            reason = (
                f"Indicator not enriched, pattern_type {pattern_type!r} "
                f"is not supported (only 'stix' indicators are enriched)"
            )
            self.helper.connector_logger.info(
                reason,
                meta={
                    "pattern_type": pattern_type,
                    "observable_type": ioc_type,
                },
            )
            return False, reason

        if not ioc_type or ioc_type.lower() not in (
            v.lower() for v in self.config.indicator_type_enrichable
        ):
            reason = (
                f"Indicator not enriched, observable type {ioc_type!r} "
                f"is not in indicator_type_enrichable"
            )
            self.helper.connector_logger.info(
                reason,
                meta={
                    "observable_type": ioc_type,
                    "pattern_type": pattern_type,
                    "enrichable_types": self.config.indicator_type_enrichable,
                },
            )
            return False, reason

        return True, None

    def process_message(self, data: dict) -> str:
        """
        Get the observable created/modified in OpenCTI and check which type to send for process
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param data: dict of data to process
        :return: string
        """
        try:
            self.helper.connector_logger.info("Starting enrichment")

            opencti_entity = data["enrichment_entity"]

            # To enrich the data, you can add more STIX object in stix_objects
            stix_objects_list = data["stix_objects"]
            indicator = data["stix_entity"]

            self.helper.connector_logger.debug(
                "Processing message",
                meta={"entity_id": data.get("entity_id")},
            )

            in_scope, scope_reason = self.entity_in_scope(data)
            if not in_scope:
                # Out-of-scope path. For a non-playbook trigger
                # (``event_type`` absent on a direct enrichment
                # request) we forward the upstream bundle untouched so
                # the work is recorded as completed; for a playbook
                # trigger we simply return the rejection reason so
                # the worker queue status reflects *why* the indicator
                # was skipped (entity-type-scope mismatch vs.
                # observable-type-not-enrichable). ``scope_reason`` is
                # guaranteed non-empty by the contract on
                # ``entity_in_scope``; fall back defensively just in
                # case a future refactor regresses that.
                if not data.get("event_type"):
                    return self._send_bundle(stix_objects_list)
                return scope_reason or "Indicator not enriched"

            # Calculate the score of the Indicator
            direct_relations = self.client.get_direct_relations(opencti_entity["id"])
            self.helper.connector_logger.debug(
                "Direct relations fetched",
                meta={"count": len(direct_relations)},
            )

            report_relations = []
            if self.config.browse_report:
                report_relations = self.client.get_report_relations(
                    opencti_entity["id"]
                )
                self.helper.connector_logger.debug(
                    "Report relations fetched",
                    meta={"count": len(report_relations)},
                )

            # Dedupe direct and report-derived relations on ``id`` so an
            # entity that participates both directly and via a Report
            # only contributes once to the score. Defensive
            # ``r.get("id")`` rather than ``r["id"]`` so a malformed /
            # partially-populated edge (no ``id`` key, ``None`` id,
            # non-dict) can never crash the whole enrichment before the
            # scope check could short-circuit — the missing-id entry is
            # silently skipped instead.
            all_relations = direct_relations + report_relations
            merged: dict[str, dict] = {}
            for r in all_relations:
                if not isinstance(r, dict):
                    continue
                rid = r.get("id")
                if rid and rid not in merged:
                    merged[rid] = r
            indicator_context = list(merged.values())

            author_id = indicator.get("created_by_ref")
            indicator_author = self.client.get_author(author_id) if author_id else None

            enriched_indicator = self._compute_score(
                indicator, indicator_context, indicator_author
            )
            # ``_compute_score`` always returns the enriched indicator
            # (in-place mutation of the passed-in dict), so this
            # bundle is always exactly one SDO. The previous
            # ``if not stix_objects: return "No information found"``
            # branch was unreachable dead code — ``[enriched_indicator]``
            # is never empty — and obscured the actual control flow
            # by suggesting an empty-bundle outcome that the helper
            # cannot produce. Forward straight to the bundle send.
            return self._send_bundle([enriched_indicator])
        except Exception as err:
            # Logger.error returns ``None``; build the message
            # ourselves so the callback's return contract holds and
            # the platform's worker queue logs surface the actual
            # failure.
            err_msg = f"Unexpected error occurred: {err}"
            self.helper.connector_logger.error(
                err_msg,
                meta={"error_message": str(err)},
            )
            return err_msg

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        info_msg = (
            "Sending " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
        )
        return info_msg

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)
