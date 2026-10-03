# pragma: no cover  # do not compute coverage on test files
# type: ignore
"""Fixtures of the deployment write-back tests."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.stream.deployment import (
    DeploymentAssuranceOptions,
    DeploymentReporter,
)

ALL_MUTATIONS = (
    "indicatorReportDeployment",
    "indicatorReportDeployments",
    "indicatorReportHits",
)
PLATFORM_ID = "c5b8a3c4-1b2a-4a8e-9a55-5a0f7a1b2c3d"
INDICATOR_ID = "0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"
INDICATOR_STIX_ID = "indicator--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9"
OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PYCTI_HELPER_METHODS = [
    "api",
    "connector_logger",
    "report_indicator_deployment",
    "report_indicator_deployments",
    "report_indicator_hits",
    "get_or_create_security_platform",
    "list_indicator_deployments",
]


class GraphQLRouter:
    """Fake ``helper.api.query`` dispatching on the GraphQL operation name."""

    def __init__(self, mutations=ALL_MUTATIONS, platform_id=PLATFORM_ID):
        self.calls: list[tuple[str, dict]] = []
        self.handlers: dict[str, Any] = {
            "DeploymentWriteBackFeatures": {
                "data": {"__type": {"fields": [{"name": name} for name in mutations]}}
            },
            "DeploymentSecurityPlatformAdd": {
                "data": {
                    "securityPlatformAdd": {
                        "id": platform_id,
                        "standard_id": "identity--1f8a7b6c-5d4e-4f3a-9b2c-1d0e9f8a7b6c",
                        "name": "Test Platform",
                    }
                }
            },
            "IndicatorReportDeployments(": lambda variables: {
                "data": {
                    "indicatorReportDeployments": {
                        "processed": len(variables["reports"]),
                        "created": 0,
                        "updated": len(variables["reports"]),
                        "unchanged": 0,
                        "errors": [],
                    }
                }
            },
            "IndicatorReportDeployment(": {
                "data": {"indicatorReportDeployment": {"id": "relationship-id"}}
            },
            "IndicatorReportHits(": {
                "data": {"indicatorReportHits": {"id": "sighting-id"}}
            },
            "IndicatorDeploymentsOfPlatform": {
                "data": {
                    "stixCoreRelationships": {
                        "edges": [],
                        "pageInfo": {"endCursor": None, "hasNextPage": False},
                    }
                }
            },
        }

    def __call__(self, query, variables=None):
        self.calls.append((query, variables))
        for marker, handler in self.handlers.items():
            if marker in query:
                result = handler(variables) if callable(handler) else handler
                if isinstance(result, BaseException):
                    raise result
                return result
        raise AssertionError(f"Unexpected GraphQL document: {query}")

    def calls_of(self, marker):
        """Return the variables of the calls whose document contains ``marker``."""
        return [variables for query, variables in self.calls if marker in query]


def deployment_node(
    indicator_id=INDICATOR_ID,
    status="deployed",
    pattern="[ipv4-addr:value = '198.51.100.7']",
    external_id=None,
    revoked=False,
    indicator_revoked=False,
    valid_until=None,
    last_hit_at=None,
    standard_id=INDICATOR_STIX_ID,
):
    """Build a ``stixCoreRelationships`` node of a deployed-on relationship."""
    return {
        "id": f"relationship-{indicator_id}",
        "deployment_status": status,
        "external_id": external_id,
        "revoked": revoked,
        "last_sync_at": "2026-10-01T00:00:00.000Z",
        "last_hit_at": last_hit_at,
        "hit_count": 0,
        "from": {
            "id": indicator_id,
            "standard_id": standard_id,
            "name": "indicator name",
            "pattern": pattern,
            "pattern_type": "stix",
            "revoked": indicator_revoked,
            "valid_until": valid_until,
            "x_opencti_main_observable_type": "IPv4-Addr",
        },
    }


def stream_indicator(indicator_id=INDICATOR_ID, stix_id=INDICATOR_STIX_ID):
    """Build the ``data`` of a stream event for an indicator."""
    return {
        "type": "indicator",
        "id": stix_id,
        "pattern": "[ipv4-addr:value = '198.51.100.7']",
        "pattern_type": "stix",
        "extensions": {
            OPENCTI_EXTENSION_ID: {"id": indicator_id, "type": "Indicator"},
        },
    }


@pytest.fixture
def ids():
    """Identifiers used by the fake responses."""
    return SimpleNamespace(
        platform=PLATFORM_ID,
        indicator=INDICATOR_ID,
        indicator_stix=INDICATOR_STIX_ID,
        extension=OPENCTI_EXTENSION_ID,
    )


@pytest.fixture
def router_factory():
    """Build GraphQL routers (custom mutations or platform id)."""
    return GraphQLRouter


@pytest.fixture
def node_factory():
    """Build deployed-on relationship nodes."""
    return deployment_node


@pytest.fixture
def indicator_factory():
    """Build stream event indicators."""
    return stream_indicator


@pytest.fixture
def router():
    """GraphQL router with every write-back mutation available."""
    return GraphQLRouter()


@pytest.fixture
def graphql_helper(router):
    """Helper without the pycti deployment helpers (GraphQL path)."""
    helper = MagicMock(spec=["api", "connector_logger"])
    helper.api.query.side_effect = router
    return helper


@pytest.fixture
def pycti_helper(router):
    """Helper shipping the pycti deployment helpers."""
    helper = MagicMock(spec=PYCTI_HELPER_METHODS)
    helper.api.query.side_effect = router
    helper.get_or_create_security_platform.return_value = {
        "id": PLATFORM_ID,
        "standard_id": "identity--1f8a7b6c-5d4e-4f3a-9b2c-1d0e9f8a7b6c",
        "name": "Test Platform",
    }
    helper.report_indicator_deployment.return_value = {"id": "relationship-id"}
    helper.report_indicator_deployments.return_value = {
        "processed": 1,
        "created": 1,
        "updated": 0,
        "unchanged": 0,
        "errors": [],
    }
    helper.report_indicator_hits.return_value = {"id": "sighting-id"}
    helper.list_indicator_deployments.return_value = iter([])
    return helper


@pytest.fixture
def options():
    """Deployment options of a test connector."""
    return DeploymentAssuranceOptions(
        security_platform_name="Test Platform",
        security_platform_type="EDR",
    )


@pytest.fixture
def no_atexit(monkeypatch):
    """Do not register exit handlers during tests."""
    registered = []
    monkeypatch.setattr(
        "connectors_sdk.connectors.stream.deployment.reporter.atexit.register",
        registered.append,
    )
    return registered


@pytest.fixture
def make_reporter(options, no_atexit):
    """Build reporters that never sleep nor flush on a timer during tests."""

    def _make(helper, reporter_options=None, **kwargs):
        kwargs.setdefault("sleep", lambda _seconds: None)
        kwargs.setdefault("flush_interval", 3600.0)
        return DeploymentReporter(helper, reporter_options or options, **kwargs)

    return _make
