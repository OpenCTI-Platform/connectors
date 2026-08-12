"""End-to-end tests for network IOC extraction (#43).

Runs against a live Docker Compose stack (OpenCTI + connector + PolySwarm API).
Verifies that enrichment creates network IOC observables (IPs, domains, URLs)
with communicates-with relationships back to the file observable.

Assertions are pinned to exact IOC data per hash so regressions are caught.

Requires:
    docker compose up -d   (the full stack must be running)

Run:
    OPENCTI_URL=http://localhost:8080 \
    OPENCTI_TOKEN=<admin-token> \
    POLYSWARM_API_KEY=<key> \
    python -m pytest polyswarm-enrichment/tests/test_e2e_network_iocs.py -v -s
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
# Config — skip entire module if env vars not set
# ---------------------------------------------------------------------------
OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "")
POLYSWARM_API_KEY = os.getenv("POLYSWARM_API_KEY", "")

pytestmark = pytest.mark.skipif(
    not OPENCTI_TOKEN,
    reason="OPENCTI_TOKEN not set — skipping e2e tests (need running stack)",
)

# ---------------------------------------------------------------------------
# Test hashes — samples with known IOC data
# ---------------------------------------------------------------------------
# Rhadamanthys — infostealer with 11 public IPs, 3 TTPs, imphash
RHADAMANTHYS_SHA256 = "7c34cccd3f58c144f561493c511a1a96a227cba58d4e1a737c4cd1b3a8a407ff"

# DTrack — RAT with imphash but no network IOCs
DTRACK_SHA256 = "cde049c032be6f7971c317a2102f88949e714d371c139f6015e1ce10cff90f18"

# Expected Rhadamanthys IPs (pinned from live API response).
# NOTE: Live API data may drift over time — update if tests fail on fresh cassettes.
RHADAMANTHYS_EXPECTED_IPS = {
    "179.43.142.201",
    "74.178.76.44",
    "23.38.111.119",
    "199.232.210.172",
    "199.232.214.172",
    "135.233.95.144",
    "40.119.249.228",
    "52.123.251.28",
    "52.185.211.133",
    "52.191.219.104",
    "72.147.149.16",
}

RHADAMANTHYS_EXPECTED_TTPS = {"T1071", "T1027", "T1027.002"}
RHADAMANTHYS_EXPECTED_IMPHASH = "49d57250c01123af7161754f5cf54349"
DTRACK_EXPECTED_IMPHASH = "83d82fdd33185880a0d3ad227636a4cf"

# Timeouts — first ingest on a clean OpenCTI is slow (~15 min for a
# 120-object bundle). The worker creates every entity individually.
# Subsequent runs with cached entities are much faster (~2-3 min).
ENRICHMENT_TIMEOUT = 900
RELATIONSHIP_TIMEOUT = 180
POLL_INTERVAL = 10


# ---------------------------------------------------------------------------
# GraphQL helper
# ---------------------------------------------------------------------------
def graphql(query: str, variables: dict = None) -> dict:
    """Execute a GraphQL query against OpenCTI."""
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


def create_observable_via_pycti(sha256: str, description: str = "") -> dict:
    """Create a StixFile observable using pycti (triggers auto-enrichment)."""
    octi = get_octi()
    return octi.stix_cyber_observable.create(
        observableData={
            "type": "file",
            "hashes": {"SHA-256": sha256},
            "x_opencti_description": description or f"E2E IOC test {sha256[:16]}",
        },
        x_opencti_score=50,
    )


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------
def get_observable_by_hash(sha256: str) -> dict | None:
    """Look up a StixFile observable by SHA-256 hash."""
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
    """Get Notes linked to an observable."""
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
    """Get relationships connected to an observable, optionally filtered by type."""
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
                first: 200
            ) {
                edges {
                    node {
                        id
                        relationship_type
                        confidence
                        from {
                            ... on StixFile { observable_value entity_type }
                            ... on IPv4Addr { observable_value entity_type }
                            ... on IPv6Addr { observable_value entity_type }
                            ... on DomainName { observable_value entity_type }
                            ... on Url { observable_value entity_type }
                            ... on Malware { name entity_type }
                            ... on Indicator { name entity_type }
                        }
                        to {
                            ... on StixFile { observable_value entity_type }
                            ... on IPv4Addr { observable_value entity_type }
                            ... on IPv6Addr { observable_value entity_type }
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


def get_observables_by_type(entity_type: str, search: str = None) -> list[dict]:
    """Get all observables of a given type, optionally filtering by value."""
    search_arg = f', search: "{search}"' if search else ""
    query = """
        {
            stixCyberObservables(
                types: ["%s"]%s
                first: 100
            ) {
                edges {
                    node {
                        id
                        observable_value
                        entity_type
                        x_opencti_score
                        x_opencti_description
                        objectLabel { value }
                        createdBy { name }
                    }
                }
            }
        }
    """ % (
        entity_type,
        search_arg,
    )
    result = graphql(query)
    return [e["node"] for e in result["stixCyberObservables"]["edges"]]


def connector_is_active() -> bool:
    """Check if the PolySwarm enrichment connector is registered and active."""
    result = graphql("{ connectors { name active connector_type } }")
    for c in result["connectors"]:
        if "polyswarm" in c["name"].lower() and c["active"]:
            return True
    return False


def delete_observable(sha256: str):
    """Delete an existing observable so re-enrichment can be triggered."""
    obs = get_observable_by_hash(sha256)
    if obs:
        try:
            octi = get_octi()
            octi.stix_cyber_observable.delete(id=obs["id"])
            time.sleep(2)
        except Exception:
            pass


def wait_for_enrichment(
    sha256: str, timeout: int = ENRICHMENT_TIMEOUT, min_rels: int = 1
) -> dict:
    """Poll until the observable has been enriched (Notes + relationships appear)."""
    deadline = time.time() + timeout
    obs = None
    while time.time() < deadline:
        obs = get_observable_by_hash(sha256)
        if obs:
            notes = get_notes_for_observable(obs["id"])
            if notes:
                # Wait for relationships to stabilize
                rel_deadline = time.time() + RELATIONSHIP_TIMEOUT
                prev_count = 0
                stable_checks = 0
                while time.time() < rel_deadline:
                    rels = get_relationships_from(obs["id"])
                    cur_count = len(rels)
                    if cur_count >= min_rels and cur_count == prev_count:
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
    """Verify the OpenCTI stack and connector are running.

    The feeder service uses a docker compose profile ("feed") and does NOT
    start by default, so there's nothing to stop here.
    """
    try:
        resp = requests.get(f"{OPENCTI_URL}/", timeout=10)
        resp.raise_for_status()
    except Exception as e:
        pytest.skip(f"OpenCTI not reachable at {OPENCTI_URL}: {e}")

    if not connector_is_active():
        pytest.skip("PolySwarm enrichment connector is not active")

    yield


@pytest.fixture(scope="session")
def rhadamanthys_enriched():
    """Create Rhadamanthys observable and wait for enrichment.

    Deletes any existing observable first to ensure re-enrichment
    happens with the current connector code (including IOC extraction).
    """
    sha256 = RHADAMANTHYS_SHA256
    delete_observable(sha256)
    create_observable_via_pycti(sha256, "E2E IOC test: Rhadamanthys")
    enriched = wait_for_enrichment(sha256, min_rels=2)
    yield enriched


@pytest.fixture(scope="session")
def dtrack_enriched():
    """Create DTrack observable and wait for enrichment.

    DTrack has 0 network IOCs so we only require 1 relationship (related-to).
    """
    sha256 = DTRACK_SHA256
    delete_observable(sha256)
    create_observable_via_pycti(sha256, "E2E IOC test: DTrack")
    enriched = wait_for_enrichment(sha256, min_rels=1)
    yield enriched


# ---------------------------------------------------------------------------
# Tests: Rhadamanthys (IOC-rich sample)
# ---------------------------------------------------------------------------
class TestRhadamanthysNetworkIOCs:
    """Rhadamanthys should produce network IOC observables."""

    def test_communicates_with_relationships_exist(self, rhadamanthys_enriched):
        """The file observable should have communicates-with relationships."""
        rels = get_relationships_from(
            rhadamanthys_enriched["id"], rel_type="communicates-with"
        )
        assert (
            len(rels) > 0
        ), "Expected communicates-with relationships for Rhadamanthys"

    def test_expected_ips_created(self, rhadamanthys_enriched):
        """All expected public IPs should appear as observables."""
        rels = get_relationships_from(
            rhadamanthys_enriched["id"], rel_type="communicates-with"
        )

        # Collect IP values from the relationship targets
        found_ips = set()
        for rel in rels:
            for side in ("from", "to"):
                node = rel.get(side) or {}
                if node.get("entity_type") in ("IPv4-Addr", "IPv6-Addr"):
                    found_ips.add(node["observable_value"])

        missing = RHADAMANTHYS_EXPECTED_IPS - found_ips
        assert not missing, (
            f"Expected IPs not found as observables: {missing}. "
            f"Found IPs: {found_ips}"
        )

    def test_ip_count_matches(self, rhadamanthys_enriched):
        """Rhadamanthys should have exactly 11 IP observables."""
        rels = get_relationships_from(
            rhadamanthys_enriched["id"], rel_type="communicates-with"
        )
        ip_rels = []
        for rel in rels:
            for side in ("from", "to"):
                node = rel.get(side) or {}
                if node.get("entity_type") in ("IPv4-Addr", "IPv6-Addr"):
                    ip_rels.append(rel)
                    break
        assert len(ip_rels) == len(RHADAMANTHYS_EXPECTED_IPS), (
            f"Expected {len(RHADAMANTHYS_EXPECTED_IPS)} IP relationships, "
            f"got {len(ip_rels)}"
        )

    def test_ip_observables_have_sandbox_label(self, rhadamanthys_enriched):
        """IP observables should be labeled polyswarm:sandbox-observed."""
        rels = get_relationships_from(
            rhadamanthys_enriched["id"], rel_type="communicates-with"
        )
        for rel in rels:
            for side in ("from", "to"):
                node = rel.get(side) or {}
                if node.get("entity_type") in ("IPv4-Addr", "IPv6-Addr"):
                    ip_value = node["observable_value"]
                    # Look up the full IP observable to check labels
                    ip_obs_list = get_observables_by_type("IPv4-Addr", search=ip_value)
                    if not ip_obs_list:
                        ip_obs_list = get_observables_by_type(
                            "IPv6-Addr", search=ip_value
                        )
                    if ip_obs_list:
                        labels = [
                            l["value"] for l in ip_obs_list[0].get("objectLabel", [])
                        ]
                        assert "polyswarm:sandbox-observed" in labels, (
                            f"IP {ip_value} missing sandbox-observed label. "
                            f"Labels: {labels}"
                        )
                    break

    def test_ip_observables_have_low_score(self, rhadamanthys_enriched):
        """IP observables should have a low score (sandbox-observed, not confirmed)."""
        rels = get_relationships_from(
            rhadamanthys_enriched["id"], rel_type="communicates-with"
        )
        for rel in rels:
            for side in ("from", "to"):
                node = rel.get(side) or {}
                if node.get("entity_type") in ("IPv4-Addr", "IPv6-Addr"):
                    ip_value = node["observable_value"]
                    ip_obs_list = get_observables_by_type("IPv4-Addr", search=ip_value)
                    if ip_obs_list:
                        score = ip_obs_list[0].get("x_opencti_score", 0)
                        assert (
                            score <= 30
                        ), f"IP {ip_value} has score {score}, expected <= 30"
                    break

    def test_ip_observables_created_by_polyswarm(self, rhadamanthys_enriched):
        """IP observables should be attributed to the PolySwarm identity."""
        rels = get_relationships_from(
            rhadamanthys_enriched["id"], rel_type="communicates-with"
        )
        for rel in rels:
            for side in ("from", "to"):
                node = rel.get(side) or {}
                if node.get("entity_type") in ("IPv4-Addr", "IPv6-Addr"):
                    ip_value = node["observable_value"]
                    ip_obs_list = get_observables_by_type("IPv4-Addr", search=ip_value)
                    if ip_obs_list and ip_obs_list[0].get("createdBy"):
                        author = ip_obs_list[0]["createdBy"]["name"]
                        assert (
                            "polyswarm" in author.lower()
                        ), f"IP {ip_value} createdBy {author}, expected PolySwarm"
                    break

    def test_communicates_with_confidence_is_low(self, rhadamanthys_enriched):
        """Communicates-with relationships should have low confidence (30)."""
        rels = get_relationships_from(
            rhadamanthys_enriched["id"], rel_type="communicates-with"
        )
        for rel in rels:
            conf = rel.get("confidence", 0)
            assert (
                conf <= 50
            ), f"Expected low confidence on communicates-with, got {conf}"


# ---------------------------------------------------------------------------
# Tests: DTrack (no network IOCs)
# ---------------------------------------------------------------------------
class TestDTrackNoNetworkIOCs:
    """DTrack should NOT produce network IOC observables (0 IPs in sandbox data)."""

    def test_no_communicates_with_relationships(self, dtrack_enriched):
        """DTrack should have no communicates-with relationships."""
        rels = get_relationships_from(
            dtrack_enriched["id"], rel_type="communicates-with"
        )
        assert (
            len(rels) == 0
        ), f"Expected 0 communicates-with for DTrack, got {len(rels)}"

    def test_enrichment_still_created_note(self, dtrack_enriched):
        """Even without IOCs, enrichment should still create a PolySwarm Note."""
        notes = get_notes_for_observable(dtrack_enriched["id"])
        assert len(notes) >= 1, "DTrack should still have a PolySwarm Note"

    def test_enrichment_still_created_malware(self, dtrack_enriched):
        """DTrack should still have malware/related-to relationships."""
        rels = get_relationships_from(dtrack_enriched["id"], rel_type="related-to")
        assert (
            len(rels) >= 1
        ), "DTrack should still have related-to relationships (malware family)"


# ---------------------------------------------------------------------------
# Tests: Relationship structure validation
# ---------------------------------------------------------------------------
class TestRelationshipStructure:
    """Validate the communicates-with relationship graph structure."""

    def test_relationship_source_is_file(self, rhadamanthys_enriched):
        """Source of communicates-with should be the file observable."""
        rels = get_relationships_from(
            rhadamanthys_enriched["id"], rel_type="communicates-with"
        )
        for rel in rels:
            from_node = rel.get("from") or {}
            to_node = rel.get("to") or {}
            # One side should be the file, the other the network observable
            entity_types = {
                from_node.get("entity_type"),
                to_node.get("entity_type"),
            }
            assert (
                "StixFile" in entity_types
            ), f"Expected StixFile in relationship, got types: {entity_types}"

    def test_relationship_targets_are_network_observables(self, rhadamanthys_enriched):
        """Targets of communicates-with should be network observables."""
        rels = get_relationships_from(
            rhadamanthys_enriched["id"], rel_type="communicates-with"
        )
        network_types = {"IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url"}
        for rel in rels:
            from_node = rel.get("from") or {}
            to_node = rel.get("to") or {}
            # The non-file side should be a network observable
            for node in (from_node, to_node):
                if node.get("entity_type") != "StixFile":
                    assert node.get("entity_type") in network_types, (
                        f"Unexpected entity type in communicates-with: "
                        f"{node.get('entity_type')}"
                    )
