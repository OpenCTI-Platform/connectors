"""Processor turning the MITRE entries of a Wiz source rule into AttackPatterns.

Wiz maps every detection rule to securitySubCategories spanning several
frameworks: the two MITRE matrices, and its own risk taxonomies. Only the
MITRE ones describe adversary behaviour, and only their externalIds are MITRE
ids, so they are the only ones converted.

No API call is made here: the sub-categories are already part of the issues
payload.
"""

import re

from connectors_sdk.models import (
    AttackPattern,
    Incident,
    KillChainPhase,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import RelationshipType
from wiz_cloud.models import WizIssue, WizSecurityCategory

# Compared lowercased and stripped, because the names are free text from Wiz.
# Adding the Wiz proprietary frameworks here is not enough on its own: their
# externalIds are not MITRE ids and must not reach mitre_id.
_MITRE_FRAMEWORKS = frozenset({"mitre att&ck matrix", "mitre att&ck cloud matrix"})

# Wiz answers a tactic-technique composite such as TA0042-T1587.001. Only the
# technique identifies the AttackPattern; PyctiAttackPattern.generate_id keys
# on x_mitre_id alone, so sending the composite would mint an entity that
# never merges with the technique the MITRE connector imported.
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_MITRE_CHAIN = "mitre-attack"


class WizTtpsProcessor:
    """Convert the MITRE sub-categories of an issue into AttackPatterns.

    Args:
        logger: The connector logger.
        author: Author attached to every emitted object.
        marking: Marking attached to every emitted object.
    """

    def __init__(
        self,
        logger,
        author: OrganizationAuthor,
        marking: TLPMarking,
    ) -> None:
        self._logger = logger
        self._author = author
        self._marking = marking

    def objects_for_issue(self, issue: WizIssue, incident: Incident) -> list:
        """Convert every MITRE technique of an issue into bundle objects.

        Techniques are grouped by id within the issue, so one appearing under
        two tactics or through two source rules yields a single AttackPattern
        carrying both kill chain phases.

        No run-scoped cache is kept: a technique shared by several issues is
        emitted in each of their bundles. Ids are deterministic, so the repeat
        is an idempotent upsert, and it keeps every bundle self-contained.

        Args:
            issue: Parsed Wiz issue.
            incident: The Incident built for that issue, so the relationship
                points at the very object in the bundle.

        Returns:
            The AttackPatterns and their uses relationships, empty when the
            issue maps to no MITRE technique.
        """
        # technique id -> (name, ordered distinct phase names)
        techniques: dict[str, tuple[str, list[str]]] = {}

        for rule in issue.source_rules:
            for sub_category in rule.security_sub_categories or []:
                category = sub_category.category
                framework = category.framework if category else None
                name = (framework.name or "") if framework else ""
                if name.strip().lower() not in _MITRE_FRAMEWORKS:
                    continue

                match = _TECHNIQUE.search(sub_category.external_id or "")
                if match is None:
                    self._logger.debug(
                        "[WIZ-CLOUD] Skipping a MITRE entry without a technique id",
                        {
                            "issue_id": issue.id,
                            "external_id": sub_category.external_id,
                        },
                    )
                    continue

                technique = match.group(0)
                # min_length=1 on AttackPattern.name, and Wiz titles can be "".
                title = (sub_category.title or "").strip() or technique
                _, phases = techniques.setdefault(technique, (title, []))
                phase = self._phase_name(category)
                if phase and phase not in phases:
                    phases.append(phase)

        objects: list = []
        for technique, (title, phases) in techniques.items():
            attack_pattern = AttackPattern(
                name=title,
                mitre_id=technique,
                # No description: generate_id keys on mitre_id alone, so this
                # upserts onto the MITRE entity, and Wiz prose is sometimes
                # empty and can drift from ATT&CK.
                kill_chain_phases=[
                    KillChainPhase(chain_name=_MITRE_CHAIN, phase_name=phase)
                    for phase in phases
                ]
                or None,
                author=self._author,
                markings=[self._marking],
            )
            objects.append(attack_pattern)
            objects.append(
                Relationship(
                    type=RelationshipType.USES,
                    source=incident,
                    target=attack_pattern,
                    # start_time and stop_time are left unset on purpose:
                    # generate_id() hashes them, so binding them to the Wiz
                    # event window would mint a new relationship every run.
                    author=self._author,
                    markings=[self._marking],
                )
            )

        return objects

    @staticmethod
    def _phase_name(category: WizSecurityCategory | None) -> str | None:
        """Turn a MITRE tactic name into a kill chain phase name.

        Args:
            category: The sub-category's category, holding the tactic name.

        Returns:
            The ATT&CK style phase name, e.g. "resource-development", or None
            when the category carries no name.
        """
        name = (category.name or "").strip() if category else ""
        return name.lower().replace(" ", "-") if name else None
