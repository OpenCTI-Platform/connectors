"""Shared builders of the Splunk connector tests."""

import json
from types import SimpleNamespace

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PLATFORM_ID = "6c3b0f4e-2d41-4a77-8f0d-3e1c9b5a7d21"
INDICATOR_ID = "0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"
INDICATOR_STIX_ID = "indicator--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9"
SPLUNK_URL = "https://splunk.test:8089"
COLLECTION_URL = f"{SPLUNK_URL}/servicesNS/nobody/search/storage/collections"
DATA_URL = f"{COLLECTION_URL}/data/opencti"
SEARCH_URL = f"{SPLUNK_URL}/servicesNS/nobody/search/search/jobs"

DEPLOYMENT_VARIABLES = (
    "DEPLOYMENT_REPORTING_ENABLED",
    "DEPLOYMENT_RECONCILIATION_INTERVAL",
    "HITS_REPORTING_ENABLED",
    "SECURITY_PLATFORM_NAME",
    "SECURITY_PLATFORM_TYPE",
    "SECURITY_PLATFORM_ID",
    "SPLUNK_HITS_SAVED_SEARCH",
)


def make_indicator(
    indicator_id=INDICATOR_ID,
    stix_id=INDICATOR_STIX_ID,
    pattern="[ipv4-addr:value = '198.51.100.7']",
):
    """Build the `data` of a stream event for an indicator."""
    return {
        "id": stix_id,
        "type": "indicator",
        "spec_version": "2.1",
        "name": "198.51.100.7",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "extensions": {
            OPENCTI_EXTENSION_ID: {
                "id": indicator_id,
                "type": "Indicator",
                "score": 80,
                "main_observable_type": "IPv4-Addr",
            }
        },
    }


def make_message(event, data, msg_id="1696320000000-0"):
    """Build a stream message."""
    return SimpleNamespace(event=event, id=msg_id, data=json.dumps({"data": data}))


def deployment_node(
    indicator_id=INDICATOR_ID,
    status="deployed",
    pattern="[ipv4-addr:value = '198.51.100.7']",
    external_id=None,
    last_hit_at=None,
):
    """Build a `deployed-on` relationship node of the deployments listing."""
    return {
        "id": f"relationship-{indicator_id}",
        "deployment_status": status,
        "external_id": external_id,
        "revoked": False,
        "last_sync_at": "2026-10-01T00:00:00.000Z",
        "last_hit_at": last_hit_at,
        "hit_count": 0,
        "from": {
            "id": indicator_id,
            "standard_id": INDICATOR_STIX_ID,
            "name": "198.51.100.7",
            "pattern": pattern,
            "pattern_type": "stix",
            "revoked": False,
            "valid_until": None,
            "x_opencti_main_observable_type": "IPv4-Addr",
        },
    }


class GraphQLRouter:
    """Fake `helper.api.query` dispatching on the GraphQL operation name."""

    def __init__(self, deployments=None):
        self.calls = []
        self.deployments = deployments or []

    def __call__(self, query, variables=None):
        self.calls.append((query, variables))
        if "DeploymentWriteBackFeatures" in query:
            return {
                "data": {
                    "__type": {
                        "fields": [
                            {"name": "indicatorReportDeployment"},
                            {"name": "indicatorReportDeployments"},
                            {"name": "indicatorReportHits"},
                        ]
                    }
                }
            }
        if "DeploymentSecurityPlatformAdd" in query:
            return {
                "data": {
                    "securityPlatformAdd": {
                        "id": PLATFORM_ID,
                        "standard_id": "identity--7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
                        "name": "Splunk",
                    }
                }
            }
        if "IndicatorReportDeployments(" in query:
            reports = variables["reports"]
            return {
                "data": {
                    "indicatorReportDeployments": {
                        "processed": len(reports),
                        "created": 0,
                        "updated": len(reports),
                        "unchanged": 0,
                        "errors": [],
                    }
                }
            }
        if "IndicatorReportHits(" in query:
            return {"data": {"indicatorReportHits": {"id": "sighting-id"}}}
        if "IndicatorDeploymentsOfPlatform" in query:
            return {
                "data": {
                    "stixCoreRelationships": {
                        "edges": [{"node": node} for node in self.deployments],
                        "pageInfo": {"endCursor": None, "hasNextPage": False},
                    }
                }
            }
        raise AssertionError(f"Unexpected GraphQL document: {query}")

    def calls_of(self, marker):
        """Return the variables of the calls whose document contains `marker`."""
        return [variables for query, variables in self.calls if marker in query]
