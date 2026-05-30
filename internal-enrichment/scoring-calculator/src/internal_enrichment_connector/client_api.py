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

    @staticmethod
    def _check_graphql_errors(res: Any, operation: str) -> None:
        """Raise ``RuntimeError`` with a clear message on a GraphQL error response.

        The GraphQL spec allows partial-success responses where ``data``
        is populated alongside an ``errors`` array; surfacing a clean
        exception here lets ``ConnectorScoring.process_message``'s
        ``except`` handler write the underlying error to the worker
        log instead of failing later with an opaque ``KeyError`` /
        ``TypeError`` when the pagination code tries to dereference a
        missing field.
        """
        if isinstance(res, dict):
            errors = res.get("errors")
            if errors:
                raise RuntimeError(f"GraphQL error in {operation}: {errors}")

    def _paginate_relations(self, entity_id, query) -> List[Dict[str, Any]]:
        # Defensive ``.get(...)`` rather than ``res["data"]["stixCoreRelationships"]``:
        # a GraphQL error response (``{"errors": [...]}`` with no ``data`` key) or a
        # payload that omits the field would otherwise raise ``KeyError`` /
        # ``TypeError`` mid-pagination and surface as an opaque stack trace.
        # ``_check_graphql_errors`` raises a clear, contextual exception on the
        # error path; the missing-field path simply stops paginating.
        edges: List[Dict[str, Any]] = []
        cursor = None
        filters = _build_filter_relations(entity_id)
        while True:
            res = self.api.query(
                query, variables={"filters": filters, "cursor": cursor}
            )
            self._check_graphql_errors(res, "_paginate_relations")
            page = ((res or {}).get("data") or {}).get("stixCoreRelationships")
            if not page:
                break
            edges.extend(page.get("edges") or [])
            page_info = page.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
        return edges

    def _paginate_report(self, entity_id, query) -> List[Dict[str, Any]]:
        # Same defensive pattern as ``_paginate_relations`` — see docstring there
        # for the rationale (error responses, missing fields, opaque
        # ``KeyError``).
        edges: List[Dict[str, Any]] = []
        cursor = None
        filters = _build_filter_reports(entity_id)
        while True:
            res = self.api.query(
                query, variables={"filters": filters, "cursor": cursor}
            )
            self._check_graphql_errors(res, "_paginate_report")
            page = ((res or {}).get("data") or {}).get("containers")
            if not page:
                break
            edges.extend(page.get("edges") or [])
            page_info = page.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
        return edges

    def _paginate_contained_entities(self, entity_id, query) -> List[Dict[str, Any]]:
        # Same defensive pattern as the other pagination helpers, with an
        # extra guard on the intermediate ``container`` node: it can be
        # ``None`` when the container was deleted between the report-list
        # fetch and the contained-entities fetch (a legitimate race rather
        # than a GraphQL error), so we stop paginating cleanly instead of
        # raising.
        edges: List[Dict[str, Any]] = []
        cursor = None
        filters = _build_filter_contained_entities()
        while True:
            res = self.api.query(
                query, variables={"id": entity_id, "filters": filters, "cursor": cursor}
            )
            self._check_graphql_errors(res, "_paginate_contained_entities")
            container = ((res or {}).get("data") or {}).get("container")
            if not container:
                break
            page = container.get("objects")
            if not page:
                break
            edges.extend(page.get("edges") or [])
            page_info = page.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
        return edges

    def get_direct_relations(self, entity_id: str) -> List[Dict[str, Any]]:
        """Return the StixDomainObjects on the far side of every direct
        StixCoreRelationship the entity participates in.
        """
        edges = self._paginate_relations(entity_id=entity_id, query=GET_REL_QUERY)

        related_entities: List[Dict[str, Any]] = []
        for e in edges:
            if not isinstance(e, dict):
                continue
            n = e.get("node")
            if not isinstance(n, dict):
                continue
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

        related_containers: List[Dict[str, Any]] = []
        for e in report_list:
            if not isinstance(e, dict):
                continue
            node = e.get("node")
            if isinstance(node, dict) and node.get("id"):
                related_containers.append(node)

        related_entities: List[Dict[str, Any]] = []
        for container in related_containers:
            entities_list = self._paginate_contained_entities(
                entity_id=container["id"], query=GET_CONTAINED_ENTITIES
            )
            for e in entities_list:
                if not isinstance(e, dict):
                    continue
                node = e.get("node")
                if isinstance(node, dict):
                    related_entities.append(node)

        return related_entities

    def get_author(self, author_id: str) -> Optional[Dict[str, Any]]:
        """Return the StixDomainObject behind ``created_by_ref``.

        Two failure modes are deliberately distinguished:

        * **OpenCTI returns no data for the author** (e.g. a dangling
          ``created_by_ref`` whose target has been deleted between the
          indicator fetch and the author lookup) - the GraphQL payload
          is well-formed but ``data.stixDomainObject`` is ``null``.
          Returns ``None`` here so the caller's ``if indicator_author``
          guard can skip the author-impact step without raising.
        * **GraphQL error response** (auth failure, query timeout,
          schema mismatch, ...) - the response carries an ``errors``
          array. Surface this through ``_check_graphql_errors`` (same
          pattern as the pagination helpers above) so the underlying
          failure shows up in the connector worker log instead of
          being silently treated as "no author" and rolled into a
          score computation that omits the author-impact step without
          telling the operator why.

        Defensive chained ``.get(...)`` keeps the deleted-author path
        from raising ``KeyError`` on an exotic-but-still-well-formed
        payload (e.g. ``{"data": {}}``) - the error path goes through
        ``_check_graphql_errors``, not through ``KeyError``.
        """
        res = self.api.query(GET_AUTHOR_QUERY, variables={"id": author_id})
        self._check_graphql_errors(res, "get_author")
        return ((res or {}).get("data") or {}).get("stixDomainObject")
