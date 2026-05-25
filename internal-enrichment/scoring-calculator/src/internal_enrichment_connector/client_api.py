from typing import Any, Dict, List, Optional

from pycti import OpenCTIApiClient

GET_REL_QUERY = """
query RelatedCore($cursor: ID, $filters: FilterGroup) {
  stixCoreRelationships(
    first: 200
    after: $cursor
    orderBy: created_at
    orderMode: desc
    filters: $filters
  ) {
    edges {
      node {
        ... on StixCoreRelationship {
          id
          relationship_type
          from {
            ... on StixDomainObject {
              id
              standard_id
              entity_type
              objectLabel {
                value
              }
            }
          }
          to {
            ... on StixDomainObject {
              id
              standard_id
              entity_type
              objectLabel {
                value
              }
            }
          }
        }
      }
    }
    pageInfo {
      endCursor
      hasNextPage
    }
  }
}
"""

GET_AUTHOR_QUERY = """
query Author($id: String!) {
  stixDomainObject(
    id: $id
  ) {
    id
    standard_id
    entity_type
    objectLabel{
      value
    }
  }
}
"""

GET_REPORT_QUERY = """
query RelatedReports($cursor: ID, $filters: FilterGroup) {
  containers(
    first: 50
    after: $cursor
    orderBy: created
    orderMode: desc
    filters: $filters
  ) {
    edges {
      node {
        id
        standard_id
        entity_type
      }
    }
    pageInfo {
      endCursor
      hasNextPage
      globalCount
    }
  }
}
"""

GET_CONTAINED_ENTITIES = """
query ContainedEntities($id: String!, $cursor: ID, $filters: FilterGroup) {
  container(id: $id) {
    id
    objects(
      first: 200
      after: $cursor
      orderBy: name
      orderMode: desc
      filters: $filters
    ) {
      edges {
        node {
          ... on StixDomainObject {
              id
              standard_id
              entity_type
              objectLabel {
                value
              }
            }
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
}
"""


def _build_filter_relations(indicator_id: str) -> dict:
    return {
        "mode": "and",
        "filters": [
            {
                "key": "entity_type",
                "values": ["stix-core-relationship"],
                "operator": "eq",
                "mode": "or",
            }
        ],
        "filterGroups": [
            {
                "mode": "or",
                "filters": [
                    {
                        "key": "fromId",
                        "operator": "eq",
                        "values": [indicator_id],
                        "mode": "or",
                    },
                    {
                        "key": "toId",
                        "operator": "eq",
                        "values": [indicator_id],
                        "mode": "or",
                    },
                ],
                "filterGroups": [],
            }
        ],
    }


def _build_filter_reports(indicator_id: str) -> dict:
    return {
        "mode": "and",
        "filters": [
            {
                "key": "entity_type",
                "operator": "eq",
                "mode": "or",
                "values": ["Report"],
            },
            {
                "key": "objects",
                "values": [indicator_id],
                "operator": "eq",
                "mode": "or",
            },
        ],
        "filterGroups": [],
    }


def _build_filter_contained_entities() -> dict:
    return {
        "mode": "and",
        "filters": [
            {
                "key": "entity_type",
                "values": ["Stix-Domain-Object"],
                "operator": "eq",
                "mode": "and",
            },
            {
                "key": "entity_type",
                "values": ["Indicator"],
                "operator": "not_eq",
                "mode": "and",
            },
        ],
        "filterGroups": [],
    }


class ConnectorClient:
    def __init__(self, api: OpenCTIApiClient):
        """
        Initialize the client with necessary configurations
        """
        self.api = api

    def _paginate_relations(self, entity_id, query) -> List[Dict[str, Any]]:
        edges = []
        cursor = None
        filters = _build_filter_relations(entity_id)
        while True:
            res = self.api.query(
                query, variables={"filters": filters, "cursor": cursor}
            )
            data = res["data"]["stixCoreRelationships"]
            edges.extend(data["edges"])
            if not data["pageInfo"]["hasNextPage"]:
                break
            cursor = data["pageInfo"]["endCursor"]
        return edges

    def _paginate_report(self, entity_id, query) -> List[Dict[str, Any]]:
        edges = []
        cursor = None
        filters = _build_filter_reports(entity_id)
        while True:
            res = self.api.query(
                query, variables={"filters": filters, "cursor": cursor}
            )
            data = res["data"]["containers"]
            edges.extend(data["edges"])
            if not data["pageInfo"]["hasNextPage"]:
                break
            cursor = data["pageInfo"]["endCursor"]
        return edges

    def _paginate_contained_entities(self, entity_id, query) -> List[Dict[str, Any]]:
        edges = []
        cursor = None
        filters = _build_filter_contained_entities()
        while True:
            res = self.api.query(
                query, variables={"id": entity_id, "filters": filters, "cursor": cursor}
            )
            data = res["data"]["container"]["objects"]
            edges.extend(data["edges"])
            if not data["pageInfo"]["hasNextPage"]:
                break
            cursor = data["pageInfo"]["endCursor"]
        return edges

    def get_direct_relations(self, entity_id: str) -> List[Dict[str, Any]]:
        """Return the StixDomainObjects on the far side of every direct
        StixCoreRelationship the entity participates in.
        """
        edges = self._paginate_relations(entity_id=entity_id, query=GET_REL_QUERY)

        related_entities: List[Dict[str, Any]] = []
        for e in edges:
            n = e["node"]
            f, t = n.get("from"), n.get("to")
            if f and f.get("id") == entity_id and t:
                related_entities.append(t)
            elif t and t.get("id") == entity_id and f:
                related_entities.append(f)
        return related_entities

    def get_report_relations(self, entity_id: str) -> List[Dict[str, Any]]:
        """Return every StixDomainObject contained in a Report that also
        contains the given entity.
        """
        report_list = self._paginate_report(entity_id=entity_id, query=GET_REPORT_QUERY)

        related_containers = []
        for e in report_list:
            related_containers.append(e["node"])

        related_entities: List[Dict[str, Any]] = []
        for container in related_containers:
            entities_list = self._paginate_contained_entities(
                entity_id=container["id"], query=GET_CONTAINED_ENTITIES
            )
            for e in entities_list:
                related_entities.append(e["node"])

        return related_entities

    def get_author(self, author_id: str) -> Optional[Dict[str, Any]]:
        """Return the StixDomainObject behind ``created_by_ref``.

        ``None`` when OpenCTI does not know the author (e.g. a dangling
        ``created_by_ref`` whose target has been deleted) so the caller
        can skip the author-impact step instead of crashing on a
        ``None.get(...)``.

        Uses chained ``.get(...)`` rather than bracket access so a
        GraphQL error response (``{"errors": [...]}`` with no ``data``
        key, or a payload that omits ``stixDomainObject`` entirely)
        degrades to ``None`` instead of raising ``KeyError`` — the
        caller already guards on ``if indicator_author`` so the
        author-impact step is simply skipped in that case.
        """
        res = self.api.query(GET_AUTHOR_QUERY, variables={"id": author_id})
        return (res or {}).get("data", {}).get("stixDomainObject")
