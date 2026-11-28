from dataclasses import dataclass, field

DEFENDER_SOURCE_NAME = "Microsoft Defender"

# Label families written by the connector: only the current value of each family is kept on a case.
DEFENDER_LABEL_PREFIXES = (
    "defender-status:",
    "defender-classification:",
    "defender-determination:",
)

_CASES_QUERY = """
    query DefenderCaseIncidents($filters: FilterGroup, $first: Int, $after: ID) {
        caseIncidents(filters: $filters, first: $first, after: $after) {
            edges {
                node {
                    id
                    standard_id
                    name
                    updated_at
                    status { id }
                    objectLabel { id value }
                    externalReferences {
                        edges { node { source_name external_id } }
                    }
                }
            }
            pageInfo { endCursor hasNextPage }
        }
    }
"""

_PAGE_SIZE = 500


@dataclass
class ExistingCase:
    """A Case-Incident of this connector already in OpenCTI."""

    id: str
    standard_id: str
    name: str = ""
    updated_at: str = ""
    status_id: str | None = None
    labels: list[dict] = field(default_factory=list)


class CaseIncidentIndex:
    """
    The Case-Incidents this connector created, keyed by Defender incident id.

    The Case-Incident id is derived from the incident name and creation date, and Defender renames an incident as
    its alerts correlate: without this index a renamed incident would become a second case and leave the first one
    with its last status. The index lets the connector reuse the case(s) already linked to the Defender incident id
    (external reference `external_id`), list the cases still open for the reconcile pass and drop stale labels.
    """

    def __init__(self, helper):
        self.helper = helper
        self.cases: dict[str, list[ExistingCase]] = {}

    def _author_internal_id(self, author_standard_id: str) -> str | None:
        author = self.helper.api.identity.read(id=author_standard_id)
        if not isinstance(author, dict) or not isinstance(author.get("id"), str):
            return None
        return author["id"]

    def load(self, author_standard_id: str) -> None:
        """
        Read every Case-Incident created by the connector identity (paginated).
        :param author_standard_id: STIX id of the connector identity
        :return: None
        """
        self.cases = {}
        author_id = self._author_internal_id(author_standard_id)
        if not author_id:
            # First run: the connector identity does not exist yet, so neither does any case.
            return
        variables = {
            "filters": {
                "mode": "and",
                "filters": [{"key": "createdBy", "values": [author_id]}],
                "filterGroups": [],
            },
            "first": _PAGE_SIZE,
            "after": None,
        }
        while True:
            result = self.helper.api.query(_CASES_QUERY, variables)
            data = result.get("data") if isinstance(result, dict) else None
            connection = data.get("caseIncidents") if isinstance(data, dict) else None
            if not isinstance(connection, dict):
                raise ValueError("Unexpected answer to the Case-Incident listing")
            for edge in connection.get("edges") or []:
                self._add(edge.get("node") or {})
            page_info = connection.get("pageInfo") or {}
            end_cursor = page_info.get("endCursor")
            if page_info.get("hasNextPage") is not True or not end_cursor:
                break
            if end_cursor == variables["after"]:
                raise ValueError("The Case-Incident listing did not advance")
            variables["after"] = end_cursor
        for cases in self.cases.values():
            # Most recently updated first: the case Defender updates last is the reference one.
            cases.sort(key=lambda case: case.updated_at or "", reverse=True)

    def _add(self, node: dict) -> None:
        if not node.get("id") or not node.get("standard_id"):
            return
        refs = (node.get("externalReferences") or {}).get("edges") or []
        incident_ids = {
            str(ref["node"]["external_id"])
            for ref in refs
            if (ref.get("node") or {}).get("source_name") == DEFENDER_SOURCE_NAME
            and ref["node"].get("external_id")
        }
        case = ExistingCase(
            id=node["id"],
            standard_id=node["standard_id"],
            name=node.get("name") or "",
            updated_at=node.get("updated_at") or "",
            status_id=(node.get("status") or {}).get("id"),
            labels=[
                label for label in node.get("objectLabel") or [] if label.get("id")
            ],
        )
        for incident_id in incident_ids:
            self.cases.setdefault(incident_id, []).append(case)

    def targets(self, incident_id, display_name: str) -> list[tuple[str, str]]:
        """
        The (standard id, name) under which to send the Case-Incident of a Defender incident.

        Empty when the incident was never seen: the caller keeps the id derived from name and creation date.
        Otherwise one entry per existing case, so every case linked to the incident converges (status, labels).
        The reference case (the one already named as the incident, else the most recently updated) takes the
        incident's current name; any other case keeps its own name, so no update ever gives two cases the same
        name and creation date (the platform would then resolve them as one entity).
        """
        cases = self.cases.get(str(incident_id), [])
        if not cases:
            return []
        reference = next(
            (case for case in cases if case.name == display_name), cases[0]
        )
        return [
            (
                case.standard_id,
                display_name if case is reference else (case.name or display_name),
            )
            for case in cases
        ]

    def open_incident_ids(self, closed_status_ids: set[str]) -> list[str]:
        """
        Defender incident ids with at least one case whose workflow status is not a closed one.
        Least recently updated first, so a bounded reconcile pass rotates through every open case.
        """
        oldest_open: dict[str, str] = {}
        for incident_id, cases in self.cases.items():
            for case in cases:
                if case.status_id in closed_status_ids:
                    continue
                updated_at = case.updated_at or ""
                if (
                    incident_id not in oldest_open
                    or updated_at < oldest_open[incident_id]
                ):
                    oldest_open[incident_id] = updated_at
        return sorted(oldest_open, key=lambda incident_id: oldest_open[incident_id])

    def duplicates(self) -> dict[str, list[str]]:
        """Defender incident ids linked to more than one case, with the case ids."""
        return {
            incident_id: [case.id for case in cases]
            for incident_id, cases in self.cases.items()
            if len(cases) > 1
        }

    def stale_labels(self, incident_id, current_labels: list[str]) -> list[tuple]:
        """
        Labels of the Defender families that no longer hold for this incident.
        :param incident_id: Defender incident id
        :param current_labels: Labels built from the incident's current values
        :return: (case internal id, label id, label value) for each label to remove
        """
        current = {label.lower() for label in current_labels}
        stale = []
        for case in self.cases.get(str(incident_id), []):
            for label in case.labels:
                value = str(label.get("value") or "").lower()
                if value.startswith(DEFENDER_LABEL_PREFIXES) and value not in current:
                    stale.append((case.id, label["id"], label.get("value")))
        return stale
