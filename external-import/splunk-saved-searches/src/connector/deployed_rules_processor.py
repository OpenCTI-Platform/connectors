"""Import of the detection rules deployed in a security platform.

Every run reads the full rule set of the platform and sends, per rule, the
rule Indicator, its ``indicates`` relationships to ATT&CK techniques and
its deployment on the Security Platform (``active`` when enabled,
``deployed`` when disabled). Rules seen in the previous run and gone now,
or whose logic changed (new Indicator), get the ``removed`` status: the
connector state keeps the Indicator of every rule of the previous run.
When a rule fails to map, the rules missing from the run are not removed:
they cannot be told apart from it, and the next complete run reconciles them.
Rules sharing the same logic share one Indicator and one deployment.
"""

from __future__ import annotations

from abc import abstractmethod
from collections import Counter
from collections.abc import Generator, Iterable
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from connector.attack_patterns import AttackPatternResolver, attack_pattern_id
from connector.deployment import (
    STATUS_ACTIVE,
    STATUS_DEPLOYED,
    STATUS_REMOVED,
    is_deployed_on_supported,
)
from connector.detection_rule import DetectionRule, RuleSkippedError
from connector.stix_builder import RuleStixBuilder
from connectors_sdk import BaseDataProcessor

if TYPE_CHECKING:
    import stix2
    from connector.state import ConnectorState
    from connectors_sdk import BaseConnectorSettings, ExternalImportConnectorState
    from pycti import OpenCTIConnectorHelper

# Rules per STIX bundle: bounds the bundle size on large rule sets.
RULES_PER_BUNDLE = 100
# Ids per GraphQL ``ids`` filter when checking removed rule Indicators.
_LOOKUP_BATCH_SIZE = 100
# Skip reason of a rule whose mapping failed unexpectedly (not a deliberate exclusion).
SKIP_INVALID = "invalid"


class DeployedRulesProcessor(BaseDataProcessor):
    """Collect the rules of a platform and reconcile their deployment."""

    state: ConnectorState
    helper: OpenCTIConnectorHelper
    builder: RuleStixBuilder
    #: Human-readable platform name, used in log messages.
    platform_label: str
    #: Id (internal or STIX) of an existing Security Platform to deploy on.
    #: When set, it takes precedence over the platform derived from its name.
    configured_platform_id: str | None = None

    def inject_dependencies(
        self,
        settings: BaseConnectorSettings,
        helper: OpenCTIConnectorHelper,
        state: ExternalImportConnectorState,
    ) -> None:
        """Keep the helper: the run queries the platform (schema, lookups)."""
        super().inject_dependencies(settings=settings, helper=helper, state=state)
        self.helper = helper

    def post_init(self) -> None:
        """Build the vendor client, the STIX builder and the technique resolver."""
        self.attack_patterns = AttackPatternResolver(self.helper)
        self.setup()

    @abstractmethod
    def setup(self) -> None:
        """Create ``self.builder`` and the vendor API client."""

    @abstractmethod
    def to_detection_rule(self, raw_rule: Any) -> DetectionRule:
        """Map a vendor rule; raise ``RuleSkippedError`` to leave it out."""

    def external_id_for_key(self, key: str) -> str:
        """Return the vendor rule id of a rule key kept in the state."""
        return key

    def resolve_platform(self) -> None:
        """Target the configured existing Security Platform, if any.

        The platform is read at every run, so a platform created after the
        connector started is found and a rename in OpenCTI is followed. An
        id that does not designate a Security Platform fails the run rather
        than sending the deployments to another platform.
        """
        if not self.configured_platform_id:
            return
        platform = self.helper.api.identity.read(id=self.configured_platform_id)
        if not platform or platform.get("entity_type") != "SecurityPlatform":
            raise ValueError(
                f"The configured platform id {self.configured_platform_id} is not "
                "a Security Platform of the OpenCTI platform"
            )
        self.builder.target_existing_platform(platform["standard_id"], platform["name"])

    # -- transform --------------------------------------------------------
    def transform(self, raw_rules: Iterable[Any]) -> Generator[list[Any], None, None]:
        """Turn the rule set of the platform into STIX bundles."""
        run_time = datetime.now(timezone.utc)
        self.resolve_platform()
        rules, skipped = self._map_rules(raw_rules)

        deployed_on_supported = is_deployed_on_supported(self.helper)
        if not deployed_on_supported:
            self.logger.warning(
                "The platform does not define the deployed-on relationship: "
                "deployments are recorded as related-to relationships",
                {"platform": self.platform_label},
            )

        self.attack_patterns.load(
            {mitre_id for rule in rules for mitre_id in rule.techniques}
        )

        previous: dict[str, str] = dict(self.state.deployed_rules or {})
        pending: dict[str, str] = dict(self.state.pending_removals or {})
        current: dict[str, str] = {}
        statuses: Counter[str] = Counter()
        linked_techniques: set[str] = set()
        last_run = self.state.last_run

        groups = self._group_by_indicator(rules, run_time)
        for start in range(0, len(groups), RULES_PER_BUNDLE):
            objects: list[Any] = list(self.builder.common_objects)
            emitted: set[str] = set()
            for indicator, rule, group in groups[start : start + RULES_PER_BUNDLE]:
                objects.append(indicator)
                techniques: dict[str, str | None] = {}
                for member in group:
                    for mitre_id, name in member.techniques.items():
                        techniques.setdefault(mitre_id, name)
                for mitre_id, name in techniques.items():
                    target_id = attack_pattern_id(mitre_id)
                    if target_id not in emitted:
                        attack_pattern = self.attack_patterns.build(
                            mitre_id,
                            name,
                            self.builder.author.id,
                            self.builder.marking.id,
                        )
                        if attack_pattern is not None:
                            objects.append(attack_pattern)
                        emitted.add(target_id)
                    objects.append(self.builder.indicates(indicator.id, target_id))
                    linked_techniques.add(mitre_id)
                status = STATUS_ACTIVE if rule.enabled else STATUS_DEPLOYED
                objects.append(
                    self.builder.deployment(
                        indicator_id=indicator.id,
                        external_id=rule.external_id,
                        status=status,
                        last_sync_at=run_time,
                        deployed_on_supported=deployed_on_supported,
                        deployed_at=rule.created_at,
                    )
                )
                for member in group:
                    statuses[STATUS_ACTIVE if member.enabled else STATUS_DEPLOYED] += 1
                    current[member.key] = indicator.id
            yield objects

        # A rule that could not be mapped is still on the platform, and the rules
        # missing from this run cannot be told apart from it: none of them is
        # removed, their state is kept until a run maps every rule.
        complete = skipped[SKIP_INVALID] == 0
        carried: dict[str, str] = {}
        former_platform = self.state.platform_id
        if former_platform in (None, self.builder.platform_id):
            former_platform = None
            if not complete:
                carried = {k: v for k, v in previous.items() if k not in current}
                self.logger.warning(
                    "Some rules could not be mapped: the rules missing from this "
                    "run keep their deployment until a complete run",
                    {"platform": self.platform_label, "kept": len(carried)},
                )
            reconciled = {k: v for k, v in previous.items() if k not in carried}
            removed, still_pending = self._removed_rules(reconciled, current, pending)
        else:
            # Renamed platform: every deployment of the previous run targets
            # the former identity and is removed from it.
            removed, still_pending = self._removed_rules(previous, {}, pending)
        removals = list(removed.items())
        for start in range(0, len(removals), RULES_PER_BUNDLE):
            yield list(self.builder.common_objects) + [
                self.builder.deployment(
                    indicator_id=indicator_id,
                    external_id=external_id,
                    status=STATUS_REMOVED,
                    last_sync_at=run_time,
                    deployed_on_supported=deployed_on_supported,
                    removed_at=run_time,
                    platform_id=former_platform,
                )
                for indicator_id, external_id in removals[
                    start : start + RULES_PER_BUNDLE
                ]
            ]

        # A former platform keeps its state until its removals are sent.
        if former_platform is None or not still_pending:
            self.state.deployed_rules = {**carried, **current}
            # Removals that could not be checked are retried on the next run.
            self.state.pending_removals = still_pending or None
            self.state.platform_id = self.builder.platform_id
        self.logger.info(
            "Detection rules reconciled",
            {
                "platform": self.platform_label,
                "rules": len(rules),
                "active": statuses[STATUS_ACTIVE],
                "disabled": statuses[STATUS_DEPLOYED],
                "removed": len(removed),
                "updated_since_last_run": sum(
                    1
                    for rule in rules
                    if last_run is None
                    or (rule.modified_at is not None and rule.modified_at > last_run)
                ),
                "techniques": len(linked_techniques),
                "skipped": dict(skipped),
                "complete": complete,
                "relationship": (
                    "deployed-on" if deployed_on_supported else "related-to"
                ),
            },
        )

    def _map_rules(
        self, raw_rules: Iterable[Any]
    ) -> tuple[list[DetectionRule], Counter[str]]:
        rules: list[DetectionRule] = []
        keys: set[str] = set()
        skipped: Counter[str] = Counter()
        for raw_rule in raw_rules:
            try:
                rule = self.to_detection_rule(raw_rule)
            except RuleSkippedError as err:
                skipped[err.reason] += 1
                continue
            except Exception as err:  # noqa: BLE001 - one bad rule never stops the run
                self.logger.warning(
                    "Could not map a rule, skipping it",
                    {"platform": self.platform_label, "error": str(err)},
                )
                skipped[SKIP_INVALID] += 1
                continue
            if rule.key in keys:
                skipped["duplicate"] += 1
                continue
            keys.add(rule.key)
            rules.append(rule)
        return rules, skipped

    def _group_by_indicator(
        self, rules: list[DetectionRule], run_time: datetime
    ) -> list[tuple[stix2.Indicator, DetectionRule, list[DetectionRule]]]:
        """Group the rules sharing one Indicator (same logic, same pattern).

        The Indicator id derives from the pattern only, as everywhere in
        OpenCTI, so rules with the same logic are one Indicator with one
        deployment on the platform. Returns, per Indicator, the Indicator,
        the rule describing its deployment (the first enabled one, else the
        first one: the deployment is ``active`` when any rule is enabled)
        and every rule of the group.
        """
        groups: dict[str, list[tuple[stix2.Indicator, DetectionRule]]] = {}
        for rule in rules:
            indicator = self.builder.indicator(rule, run_time)
            groups.setdefault(indicator.id, []).append((indicator, rule))
        result = []
        for members in groups.values():
            indicator, rule = next(
                (member for member in members if member[1].enabled), members[0]
            )
            result.append((indicator, rule, [member[1] for member in members]))
        return result

    def _removed_rules(
        self,
        previous: dict[str, str],
        current: dict[str, str],
        pending: dict[str, str],
    ) -> tuple[dict[str, str], dict[str, str]]:
        """Find the rule Indicators no longer deployed.

        ``previous`` / ``current`` map rule keys to Indicator ids; ``pending``
        maps Indicator ids to rule ids of removals not checked yet. Returns,
        as Indicator id -> rule id, the removals to send (the Indicator still
        exists on the platform) and the ones to retry on the next run (the
        platform could not be asked). An Indicator deleted from the platform,
        or still deployed through another rule, needs nothing.
        """
        live_indicators = set(current.values())
        candidates = dict(pending)
        for key, indicator_id in previous.items():
            if current.get(key) != indicator_id:
                candidates.setdefault(indicator_id, self.external_id_for_key(key))
        candidates = {
            indicator_id: external_id
            for indicator_id, external_id in candidates.items()
            if indicator_id not in live_indicators
        }
        if not candidates:
            return {}, {}
        try:
            existing = self._existing_indicators(candidates)
        except Exception as err:  # noqa: BLE001 - retried on the next run
            self.logger.warning(
                "Could not check the removed rules against the platform, "
                "retrying on the next run",
                {"platform": self.platform_label, "error": str(err)},
            )
            return {}, candidates
        return {
            indicator_id: external_id
            for indicator_id, external_id in candidates.items()
            if indicator_id in existing
        }, {}

    def _existing_indicators(self, indicator_ids: Iterable[str]) -> set[str]:
        wanted = sorted(set(indicator_ids))
        existing: set[str] = set()
        for start in range(0, len(wanted), _LOOKUP_BATCH_SIZE):
            batch = wanted[start : start + _LOOKUP_BATCH_SIZE]
            entities = self.helper.api.indicator.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "ids", "values": batch}],
                    "filterGroups": [],
                },
                first=len(batch) * 2,
                customAttributes="standard_id x_opencti_stix_ids",
            )
            requested = set(batch)
            for entity in entities or []:
                known_ids = {entity.get("standard_id")} | set(
                    entity.get("x_opencti_stix_ids") or []
                )
                existing.update(known_ids & requested)
        return existing
