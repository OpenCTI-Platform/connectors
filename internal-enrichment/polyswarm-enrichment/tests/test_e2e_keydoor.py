"""Lightweight e2e test: Keydoor enrichment with network IOC verification.

Keydoor produces a small STIX bundle (~26 objects, no polykg profile) making
it suitable for CI.  Verifies the full enrichment pipeline including network
IOC extraction (9 IPs, 2 URLs, 2 domains).

Requires:
    docker compose -f docker-compose.test.yml -p test up -d --build

Run:
    OPENCTI_URL=http://localhost:18080 \
    OPENCTI_TOKEN=<admin-token> \
    POLYSWARM_API_KEY=<key> \
    python -m pytest polyswarm-enrichment/tests/test_e2e_keydoor.py -v -s
"""

import os
import sys
import time

import pytest
import requests

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
SRC_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "src")
sys.path.insert(0, os.path.abspath(SRC_DIR))

# ---------------------------------------------------------------------------
# Config — skip if env vars not set
# ---------------------------------------------------------------------------
OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")

pytestmark = pytest.mark.skipif(
    not OPENCTI_TOKEN,
    reason="OPENCTI_TOKEN not set — skipping e2e tests (need running stack)",
)

# Keydoor — named malware family, 9 IPs, 2 URLs, no polykg profile → ~26 STIX objects
KEYDOOR_SHA256 = "83a37ac38e86dfcccbf405650ef0ef655e2a4671bf5d8b3c405af18fb37bcb89"

KEYDOOR_EXPECTED_IPS = {
    "175.126.111.143",
    "20.72.205.209",
    "211.43.203.28",
    "23.38.111.119",
    "23.62.100.184",
    "72.145.35.144",
    "74.178.76.128",
    "74.178.76.44",
    "85.234.74.60",
}

# Timeouts — Keydoor's ~26 object bundle should ingest in ~3-4 min.
ENRICHMENT_TIMEOUT = 300
RELATIONSHIP_TIMEOUT = 120
POLL_INTERVAL = 5


# ---------------------------------------------------------------------------
# GraphQL helper
# ---------------------------------------------------------------------------
def graphql(query: str, variables: dict = None) -> dict:
    resp = requests.post(
        f"{OPENCTI_URL}/graphql",
        json={"query": query, "variables": variables or {}},
        headers={
            "Authorization": f"Bearer {OPENCTI_TOKEN}",
            "Content-Type": "application/json",
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data["data"]


# ---------------------------------------------------------------------------
# pycti helper
# ---------------------------------------------------------------------------
_octi_client = None


def get_octi():
    global _octi_client
    if _octi_client is None:
        from pycti import OpenCTIApiClient

        _octi_client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)
    return _octi_client


def create_observable(sha256: str, description: str = "") -> dict:
    octi = get_octi()
    return octi.stix_cyber_observable.create(
        observableData={
            "type": "file",
            "hashes": {"SHA-256": sha256},
            "x_opencti_description": description or "E2E Keydoor test",
        },
        x_opencti_score=50,
    )


def delete_observable(sha256: str):
    obs = get_observable_by_hash(sha256)
    if obs:
        try:
            get_octi().stix_cyber_observable.delete(id=obs["id"])
            time.sleep(2)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------
def get_observable_by_hash(sha256: str) -> dict | None:
    query = """
        {
            stixCyberObservables(
                filters: {
                    mode: and
                    filters: [{key: "hashes.SHA-256", values: ["%s"]}]
                    filterGroups: []
                }
            ) {
                edges {
                    node {
                        id
                        observable_value
                        entity_type
                        x_opencti_score
                        ... on StixFile { hashes { algorithm hash } }
                        objectLabel { value }
                    }
                }
            }
        }
    """ % sha256
    result = graphql(query)
    edges = result["stixCyberObservables"]["edges"]
    return edges[0]["node"] if edges else None


def get_notes_for_observable(observable_id: str) -> list[dict]:
    query = """
        {
            notes(
                filters: {
                    mode: and
                    filters: [{key: "objects", values: ["%s"]}]
                    filterGroups: []
                }
            ) {
                edges { node { id attribute_abstract content } }
            }
        }
    """ % observable_id
    result = graphql(query)
    return [e["node"] for e in result["notes"]["edges"]]


def get_relationships_from(observable_id: str, rel_type: str = None) -> list[dict]:
    query = """
        {
            stixCoreRelationships(
                filters: {
                    mode: or
                    filters: [
                        {key: "fromId", values: ["%s"]}
                        {key: "toId", values: ["%s"]}
                    ]
                    filterGroups: []
                }
                first: 100
            ) {
                edges {
                    node {
                        id
                        relationship_type
                        confidence
                        from {
                            ... on StixFile { observable_value entity_type }
                            ... on IPv4Addr { observable_value entity_type }
                            ... on DomainName { observable_value entity_type }
                            ... on Url { observable_value entity_type }
                            ... on Malware { name entity_type }
                            ... on Indicator { name entity_type }
                        }
                        to {
                            ... on StixFile { observable_value entity_type }
                            ... on IPv4Addr { observable_value entity_type }
                            ... on DomainName { observable_value entity_type }
                            ... on Url { observable_value entity_type }
                            ... on Malware { name entity_type }
                            ... on Indicator { name entity_type }
                        }
                    }
                }
            }
        }
    """ % (
        observable_id,
        observable_id,
    )
    result = graphql(query)
    rels = [e["node"] for e in result["stixCoreRelationships"]["edges"]]
    if rel_type:
        rels = [r for r in rels if r["relationship_type"] == rel_type]
    return rels


def get_malware_by_name(name: str) -> dict | None:
    result = graphql(
        """
        query GetMalware($search: String) {
            malwares(search: $search) {
                edges { node { id name malware_types is_family } }
            }
        }
        """,
        {"search": name},
    )
    edges = result["malwares"]["edges"]
    for e in edges:
        if e["node"]["name"].lower() == name.lower():
            return e["node"]
    return edges[0]["node"] if edges else None


def connector_is_active() -> bool:
    result = graphql("{ connectors { name active connector_type } }")
    for c in result["connectors"]:
        if "polyswarm" in c["name"].lower() and c["active"]:
            return True
    return False


def wait_for_enrichment(sha256: str, timeout: int = ENRICHMENT_TIMEOUT) -> dict:
    """Poll until enrichment completes (notes + relationships stabilize)."""
    deadline = time.time() + timeout
    obs = None
    while time.time() < deadline:
        obs = get_observable_by_hash(sha256)
        if obs:
            notes = get_notes_for_observable(obs["id"])
            if notes:
                rel_deadline = time.time() + RELATIONSHIP_TIMEOUT
                prev_count = 0
                stable_checks = 0
                while time.time() < rel_deadline:
                    rels = get_relationships_from(obs["id"])
                    cur_count = len(rels)
                    if cur_count >= 3 and cur_count == prev_count:
                        stable_checks += 1
                        if stable_checks >= 2:
                            return obs
                    else:
                        stable_checks = 0
                    prev_count = cur_count
                    time.sleep(POLL_INTERVAL)
                return obs
        time.sleep(POLL_INTERVAL)
    pytest.fail(
        f"Enrichment did not complete within {timeout}s for {sha256[:16]}. "
        f"Observable found: {obs is not None}"
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def check_stack():
    """Verify the OpenCTI stack and connector are running."""
    try:
        resp = requests.get(f"{OPENCTI_URL}/", timeout=10)
        resp.raise_for_status()
    except Exception as e:
        pytest.skip(f"OpenCTI not reachable at {OPENCTI_URL}: {e}")

    if not connector_is_active():
        pytest.skip("PolySwarm enrichment connector is not active")

    yield


@pytest.fixture(scope="session")
def keydoor_enriched():
    """Create Keydoor observable, wait for enrichment. Session-scoped."""
    sha256 = KEYDOOR_SHA256
    delete_observable(sha256)
    create_observable(sha256, "E2E Keydoor IOC test")
    return wait_for_enrichment(sha256)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestKeydoorEnrichment:
    """Core enrichment: note, indicator, malware."""

    def test_note_exists(self, keydoor_enriched):
        notes = get_notes_for_observable(keydoor_enriched["id"])
        assert len(notes) >= 1

    def test_note_has_polyscore(self, keydoor_enriched):
        notes = get_notes_for_observable(keydoor_enriched["id"])
        assert "PolyScore:" in notes[0]["content"]

    def test_malware_relationship_exists(self, keydoor_enriched):
        rels = get_relationships_from(keydoor_enriched["id"], rel_type="related-to")
        assert len(rels) >= 1

    def test_malware_named_keydoor(self, keydoor_enriched):
        malware = get_malware_by_name("Keydoor")
        assert malware is not None
        assert malware["name"] == "Keydoor"
        assert malware["is_family"] is True

    def test_score_above_default(self, keydoor_enriched):
        score = keydoor_enriched.get("x_opencti_score", 0)
        assert score > 50, f"Expected score > 50, got {score}"


class TestKeydoorNetworkIOCs:
    """Network IOC extraction: communicates-with relationships to IPs."""

    def test_communicates_with_relationships_exist(self, keydoor_enriched):
        rels = get_relationships_from(
            keydoor_enriched["id"], rel_type="communicates-with"
        )
        assert len(rels) > 0, "Expected communicates-with relationships"

    def test_expected_ips_created(self, keydoor_enriched):
        rels = get_relationships_from(
            keydoor_enriched["id"], rel_type="communicates-with"
        )
        found_ips = set()
        for rel in rels:
            for side in ("from", "to"):
                node = rel.get(side) or {}
                if node.get("entity_type") in ("IPv4-Addr", "IPv6-Addr"):
                    found_ips.add(node["observable_value"])

        missing = KEYDOOR_EXPECTED_IPS - found_ips
        assert not missing, f"Expected IPs not found: {missing}. Found: {found_ips}"

    def test_ip_count_matches(self, keydoor_enriched):
        rels = get_relationships_from(
            keydoor_enriched["id"], rel_type="communicates-with"
        )
        ip_rels = []
        for rel in rels:
            for side in ("from", "to"):
                node = rel.get(side) or {}
                if node.get("entity_type") in ("IPv4-Addr", "IPv6-Addr"):
                    ip_rels.append(rel)
                    break
        assert len(ip_rels) == len(
            KEYDOOR_EXPECTED_IPS
        ), f"Expected {len(KEYDOOR_EXPECTED_IPS)} IP relationships, got {len(ip_rels)}"

    def test_communicates_with_confidence_is_low(self, keydoor_enriched):
        rels = get_relationships_from(
            keydoor_enriched["id"], rel_type="communicates-with"
        )
        for rel in rels:
            assert (
                rel.get("confidence", 0) <= 50
            ), f"Expected low confidence, got {rel.get('confidence')}"

    def test_relationship_source_is_file(self, keydoor_enriched):
        rels = get_relationships_from(
            keydoor_enriched["id"], rel_type="communicates-with"
        )
        for rel in rels:
            from_node = rel.get("from") or {}
            to_node = rel.get("to") or {}
            entity_types = {from_node.get("entity_type"), to_node.get("entity_type")}
            assert (
                "StixFile" in entity_types
            ), f"Expected StixFile in relationship, got {entity_types}"
