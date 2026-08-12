"""End-to-end tests against a running OpenCTI + PolySwarm enrichment stack.

Requires:
    docker compose up -d   (the full stack must be running)

Run:
    OPENCTI_URL=http://localhost:8080 \
    OPENCTI_TOKEN=<admin-token> \
    POLYSWARM_API_KEY=<key> \
    python -m pytest tests/test_e2e_opencti.py -v -s

These tests verify the enrichment pipeline by:
  1. Creating observables via pycti (same path as the feeder)
  2. Waiting for the enrichment connector to process them
  3. Querying OpenCTI GraphQL to verify STIX objects landed correctly
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

# Well-known hashes with stable PolySwarm results.
# WannaCry — universally detected ransomware
WANNACRY_SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
# Mimikatz — universally detected credential tool
MIMIKATZ_SHA256 = "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1"

# Max seconds to wait for enrichment to complete
ENRICHMENT_TIMEOUT = 300
RELATIONSHIP_TIMEOUT = 90
POLL_INTERVAL = 5
# The connector creates at least based-on + related-to on the observable
MIN_OBSERVABLE_RELATIONSHIPS = 2


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
# pycti helper — creates observables the same way the feeder does
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
    result = octi.stix_cyber_observable.create(
        observableData={
            "type": "file",
            "hashes": {"SHA-256": sha256},
            "x_opencti_description": description or f"E2E test {sha256[:16]}",
        },
        x_opencti_score=50,
    )
    return result


def delete_observable(internal_id: str):
    """Clean up an observable after test."""
    try:
        octi = get_octi()
        octi.stix_cyber_observable.delete(id=internal_id)
    except Exception:
        pass


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
                        x_opencti_description
                        ... on StixFile {
                            name
                            hashes { algorithm hash }
                        }
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
                edges {
                    node {
                        id
                        attribute_abstract
                        content
                    }
                }
            }
        }
    """ % observable_id
    result = graphql(query)
    return [e["node"] for e in result["notes"]["edges"]]


def get_relationships_from(observable_id: str) -> list[dict]:
    """Get all relationships connected to an observable."""
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
            ) {
                edges {
                    node {
                        id
                        relationship_type
                        from {
                            ... on StixFile { observable_value }
                            ... on Indicator { name pattern }
                            ... on Malware { name malware_types }
                        }
                        to {
                            ... on StixFile { observable_value }
                            ... on Indicator { name pattern }
                            ... on Malware { name malware_types }
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
    return [e["node"] for e in result["stixCoreRelationships"]["edges"]]


def get_indicators_for_hash(sha256: str) -> list[dict]:
    """Find STIX indicators that match a given hash."""
    result = graphql(
        """
        query GetIndicators($pattern: String!) {
            indicators(search: $pattern) {
                edges {
                    node {
                        id
                        name
                        pattern
                        indicator_types
                        x_opencti_score
                    }
                }
            }
        }
        """,
        {"pattern": sha256},
    )
    return [e["node"] for e in result["indicators"]["edges"]]


def get_malware_by_name(name: str) -> dict | None:
    """Find a malware object by name (case-insensitive search)."""
    result = graphql(
        """
        query GetMalware($search: String) {
            malwares(search: $search) {
                edges {
                    node {
                        id
                        name
                        description
                        malware_types
                        is_family
                    }
                }
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


def wait_for_enrichment(sha256: str, timeout: int = ENRICHMENT_TIMEOUT) -> dict:
    """Poll until the observable has been enriched (Notes + relationships appear)."""
    deadline = time.time() + timeout
    obs = None
    while time.time() < deadline:
        obs = get_observable_by_hash(sha256)
        if obs:
            notes = get_notes_for_observable(obs["id"])
            if notes:
                # Notes landed — now wait for the worker to finish
                # ingesting relationships from the same bundle.
                # The connector creates at least based-on + related-to
                # on the observable; wait until we see them both and
                # the count stops changing.
                rel_deadline = time.time() + RELATIONSHIP_TIMEOUT
                prev_count = 0
                stable_checks = 0
                while time.time() < rel_deadline:
                    rels = get_relationships_from(obs["id"])
                    cur_count = len(rels)
                    if (
                        cur_count >= MIN_OBSERVABLE_RELATIONSHIPS
                        and cur_count == prev_count
                    ):
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


def connector_is_active() -> bool:
    """Check if the PolySwarm enrichment connector is registered and active."""
    result = graphql("{ connectors { name active connector_type } }")
    for c in result["connectors"]:
        if "polyswarm" in c["name"].lower() and c["active"]:
            return True
    return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def check_stack():
    """Verify the OpenCTI stack and connector are running before any tests.

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
def wannacry_enriched():
    """Create WannaCry observable and wait for enrichment. Session-scoped."""
    sha256 = WANNACRY_SHA256
    obs = get_observable_by_hash(sha256)
    if not obs:
        result = create_observable_via_pycti(sha256, "E2E test: WannaCry")
        result["id"]
    else:
        obs["id"]

    enriched = wait_for_enrichment(sha256)
    yield enriched
    # Don't delete — might be reused or useful for debugging


@pytest.fixture(scope="session")
def mimikatz_enriched():
    """Create Mimikatz observable and wait for enrichment. Session-scoped."""
    sha256 = MIMIKATZ_SHA256
    obs = get_observable_by_hash(sha256)
    if not obs:
        result = create_observable_via_pycti(sha256, "E2E test: Mimikatz")
        result["id"]
    else:
        obs["id"]

    enriched = wait_for_enrichment(sha256)
    yield enriched


@pytest.fixture(scope="session")
def feeder_enriched():
    """Wait for any feeder-created observable to be enriched."""
    deadline = time.time() + ENRICHMENT_TIMEOUT
    while time.time() < deadline:
        result = graphql("""
            { stixCyberObservables(first: 20, orderBy: created_at, orderMode: desc) {
                edges { node { id observable_value x_opencti_score } }
            } }
        """)
        for edge in result["stixCyberObservables"]["edges"]:
            node = edge["node"]
            if node["x_opencti_score"] and node["x_opencti_score"] > 50:
                notes = get_notes_for_observable(node["id"])
                if notes:
                    return node
        time.sleep(POLL_INTERVAL)
    pytest.skip("No feeder-enriched observable found within timeout")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestConnectorRegistration:
    def test_connector_active(self):
        result = graphql("{ connectors { name active connector_type } }")
        enrichment = [
            c
            for c in result["connectors"]
            if "polyswarm enrichment" in c["name"].lower()
        ]
        assert len(enrichment) == 1, (
            "Expected exactly one 'PolySwarm Enrichment' connector. "
            f"Got: {[c['name'] for c in result['connectors']]}"
        )
        assert enrichment[0]["active"] is True
        assert enrichment[0]["connector_type"] == "INTERNAL_ENRICHMENT"


class TestEnrichmentCreatesNote:
    """Verify enrichment creates a PolySwarm Note with detection data."""

    def test_note_exists(self, wannacry_enriched):
        notes = get_notes_for_observable(wannacry_enriched["id"])
        assert len(notes) >= 1, "Expected at least one Note from enrichment"

    def test_note_abstract_has_detection(self, wannacry_enriched):
        notes = get_notes_for_observable(wannacry_enriched["id"])
        abstract = notes[0]["attribute_abstract"]
        assert "PolySwarm" in abstract
        assert "/" in abstract  # e.g. "15/17 engines"

    def test_note_content_has_hashes(self, wannacry_enriched):
        notes = get_notes_for_observable(wannacry_enriched["id"])
        content = notes[0]["content"]
        assert WANNACRY_SHA256 in content

    def test_note_content_has_polyscore(self, wannacry_enriched):
        notes = get_notes_for_observable(wannacry_enriched["id"])
        content = notes[0]["content"]
        assert "PolyScore:" in content

    def test_note_content_has_polyswarm_link(self, wannacry_enriched):
        notes = get_notes_for_observable(wannacry_enriched["id"])
        content = notes[0]["content"]
        assert "polyswarm.network" in content

    def test_note_content_has_file_type(self, wannacry_enriched):
        notes = get_notes_for_observable(wannacry_enriched["id"])
        content = notes[0]["content"]
        assert "MIME Type:" in content or "File Type:" in content


class TestEnrichmentCreatesIndicator:
    """Verify enrichment creates a STIX Indicator."""

    def test_indicator_exists(self, wannacry_enriched):
        indicators = get_indicators_for_hash(WANNACRY_SHA256)
        assert len(indicators) >= 1, "Expected at least one Indicator"

    def test_indicator_has_stix_pattern(self, wannacry_enriched):
        indicators = get_indicators_for_hash(WANNACRY_SHA256)
        ind = indicators[0]
        assert "file:hashes" in ind["pattern"]
        assert WANNACRY_SHA256 in ind["pattern"]


class TestEnrichmentCreatesMalware:
    """Verify enrichment creates a Malware STIX object."""

    def test_malware_relationship_exists(self, wannacry_enriched):
        rels = get_relationships_from(wannacry_enriched["id"])
        related = [r for r in rels if r["relationship_type"] == "related-to"]
        assert len(related) >= 1, (
            f"Expected related-to relationship. Types: "
            f"{[r['relationship_type'] for r in rels]}"
        )

    def test_malware_has_types(self, wannacry_enriched):
        """Malware object has malware_types populated from PolySwarm labels."""
        rels = get_relationships_from(wannacry_enriched["id"])
        for r in rels:
            for side in ("from", "to"):
                node = r.get(side) or {}
                if node.get("malware_types"):
                    assert len(node["malware_types"]) >= 1
                    return
        # If no malware_types found via relationships, check directly
        # The malware name might vary (WannaCry, Wannacrypt, etc.)
        rels_related = [r for r in rels if r["relationship_type"] == "related-to"]
        if rels_related:
            # Get malware name from relationship
            for side in ("from", "to"):
                name = (rels_related[0].get(side) or {}).get("name")
                if name:
                    malware = get_malware_by_name(name)
                    if malware and malware.get("malware_types"):
                        assert len(malware["malware_types"]) >= 1
                        return
        pytest.fail("No malware_types found on any related malware object")


class TestObservableScore:
    """Verify the observable score is updated after enrichment."""

    def test_score_above_default(self, wannacry_enriched):
        score = wannacry_enriched.get("x_opencti_score", 0)
        assert score > 50, f"Expected score > 50 (default), got {score}"

    def test_score_reflects_polyscore(self, wannacry_enriched):
        score = wannacry_enriched.get("x_opencti_score", 0)
        # WannaCry should be universally detected → high PolyScore
        assert score >= 80, f"Expected score >= 80 for WannaCry, got {score}"

    def test_feeder_observable_score_updated(self, feeder_enriched):
        """Feeder-created observables also get score updated."""
        score = feeder_enriched.get("x_opencti_score", 0)
        assert score > 50, f"Expected feeder observable score > 50, got {score}"


class TestRelationships:
    """Verify correct STIX relationships are created."""

    def test_indicator_based_on_observable(self, wannacry_enriched):
        rels = get_relationships_from(wannacry_enriched["id"])
        based_on = [r for r in rels if r["relationship_type"] == "based-on"]
        assert len(based_on) >= 1, (
            f"Expected based-on relationship. Types: "
            f"{[r['relationship_type'] for r in rels]}"
        )

    def test_observable_related_to_malware(self, wannacry_enriched):
        rels = get_relationships_from(wannacry_enriched["id"])
        related = [r for r in rels if r["relationship_type"] == "related-to"]
        assert len(related) >= 1

    def test_indicator_indicates_malware(self, wannacry_enriched):
        # The "indicates" relationship is Indicator→Malware, not through the
        # observable. Find the indicator first, then check its relationships.
        indicators = get_indicators_for_hash(WANNACRY_SHA256)
        assert indicators, "Need at least one indicator"
        indicator_id = indicators[0]["id"]
        rels = get_relationships_from(indicator_id)
        indicates = [r for r in rels if r["relationship_type"] == "indicates"]
        assert len(indicates) >= 1, (
            f"Expected indicates relationship from indicator. "
            f"Types: {[r['relationship_type'] for r in rels]}"
        )


class TestMultipleSamples:
    """Verify enrichment works for different malware families."""

    def test_mimikatz_enriched(self, mimikatz_enriched):
        notes = get_notes_for_observable(mimikatz_enriched["id"])
        assert len(notes) >= 1

    def test_mimikatz_has_different_malware(self, mimikatz_enriched):
        rels = get_relationships_from(mimikatz_enriched["id"])
        malware_names = set()
        for r in rels:
            for side in ("from", "to"):
                name = (r.get(side) or {}).get("name")
                if name and r["relationship_type"] == "related-to":
                    malware_names.add(name)
        assert len(malware_names) >= 1, "Expected at least one malware family"
