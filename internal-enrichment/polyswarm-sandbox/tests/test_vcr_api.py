"""VCR-based tests for PolySwarm API interactions.

These tests replay recorded API cassettes — no API key or network needed.
To re-record: POLYSWARM_API_KEY=<key> python tests/record_cassettes.py
"""

import io

import pytest
from connector.polyswarm_client import PolySwarmClient
from connector.sandbox_processor import SandboxProcessor
from connector.scan_processor import ScanProcessor
from polyswarm_api.api import PolyswarmAPI

from tests.conftest import (
    EICAR_SHA256,
    RHADAMANTHYS_SHA256,
    SAMPLE_SHA256,
    WANNACRY_SHA256,
    StubHelper,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def api(vcr_instance):
    """Raw PolyswarmAPI instance for low-level VCR tests."""
    return PolyswarmAPI(key="SCRUBBED")


@pytest.fixture
def client(vcr_instance):
    """PolySwarmClient wired to StubHelper (no OpenCTI needed)."""
    return PolySwarmClient(
        api_key="SCRUBBED",
        api_url="https://api.polyswarm.network/v3",
        community="default",
        timeout=30,
        helper=StubHelper(),
    )


# ── Hash Search ───────────────────────────────────────────────────────────────


class TestHashSearch:
    """Verify hash lookups return expected detection data."""

    def test_eicar_detected(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_eicar.yaml"):
            for result in api.search(EICAR_SHA256):
                assert result.polyscore > 0.99
                assert len(result.assertions) >= 10
                break

    def test_wannacry_detected(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_wannacry.yaml"):
            for result in api.search(WANNACRY_SHA256):
                assert result.polyscore > 0.99
                assert len(result.assertions) >= 10
                break

    def test_rhadamanthys_detected(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_rhadamanthys.yaml"):
            for result in api.search(RHADAMANTHYS_SHA256):
                assert result.polyscore > 0.99
                break

    def test_sample_detected(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_sample.yaml"):
            for result in api.search(SAMPLE_SHA256):
                assert result.polyscore > 0.99
                break


# ── Scan Submit + Poll ────────────────────────────────────────────────────────


class TestScanLifecycle:
    """Verify scan submission and polling with recorded EICAR scan."""

    def test_submit_returns_instance(self, api, vcr_instance):
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        with vcr_instance.use_cassette("scan_eicar_submit.yaml"):
            instance = api.submit(io.BytesIO(eicar), artifact_name="eicar.com")
            assert instance.id is not None

    def test_poll_until_complete(self, api, vcr_instance):
        """Replay recorded polling — should reach window_closed."""
        with vcr_instance.use_cassette("scan_eicar_poll.yaml"):
            # The cassette has the instance_id baked in; use the same one
            # First request returns the instance, subsequent polls follow
            instance_id = "18283207297428233"
            for _ in range(60):
                result = api.lookup(instance_id)
                if result.failed or result.window_closed:
                    break
            assert result.window_closed
            assert not result.failed
            assert result.polyscore > 0.99

    def test_scan_results_parseable(self, api, vcr_instance):
        """Verify completed scan results can be processed by ScanProcessor."""
        with vcr_instance.use_cassette("scan_eicar_poll.yaml"):
            instance_id = "18283207297428233"
            for _ in range(60):
                result = api.lookup(instance_id)
                if result.failed or result.window_closed:
                    break
            mapped = ScanProcessor.process(result.json)
            assert mapped is not None
            assert mapped.get("score") is not None
            assert mapped.get("family") is not None


# ── Sandbox Providers ─────────────────────────────────────────────────────────


class TestSandboxProviders:
    """Verify sandbox provider listing from recorded API response."""

    def test_providers_listed(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_providers.yaml"):
            providers = api.sandbox_providers()
            slugs = [p.slug for p in providers]
            assert "cape" in slugs
            assert "triage" in slugs

    def test_cape_has_vms(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_providers.yaml"):
            for p in api.sandbox_providers():
                if p.slug == "cape":
                    assert len(p.vms) > 0
                    break

    def test_client_get_available_providers(self, client, vcr_instance):
        with vcr_instance.use_cassette("sandbox_providers.yaml"):
            providers = client.get_available_providers()
            assert len(providers) >= 2
            slugs = [p["slug"] for p in providers]
            assert "cape" in slugs
            assert "triage" in slugs

    def test_client_get_default_vm(self, client, vcr_instance):
        with vcr_instance.use_cassette("sandbox_providers.yaml"):
            vm = client.get_default_vm_for_provider("cape")
            assert vm is not None


# ── Sandbox Results ───────────────────────────────────────────────────────────


class TestSandboxResults:
    """Verify sandbox result retrieval and processing from recorded tasks."""

    # ── Raw API results ───────────────────────────────────────────────

    def test_wannacry_cape_succeeded(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_cape.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "cape")
            assert task.status == "SUCCEEDED"
            assert task.report is not None
            assert "ttp" in task.report

    def test_wannacry_triage_succeeded(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_triage.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "triage")
            assert task.status == "SUCCEEDED"
            assert task.report is not None

    def test_wannacry_cape_has_network(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_cape.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "cape")
            assert "network" in task.report

    def test_wannacry_cape_has_signatures(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_cape.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "cape")
            assert "signature_names" in task.report or "signatures" in task.report

    def test_rhadamanthys_cape_succeeded(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_rhadamanthys_cape.yaml"):
            task = api.sandbox_task_latest(RHADAMANTHYS_SHA256, "cape")
            assert task.status == "SUCCEEDED"

    def test_sample_cape_succeeded(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_sample_cape.yaml"):
            task = api.sandbox_task_latest(SAMPLE_SHA256, "cape")
            assert task.status == "SUCCEEDED"

    # ── Cape parsing — WannaCry ───────────────────────────────────────

    def test_cape_wannacry_provider_detected(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_cape.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            assert processed is not None
            assert processed["provider"] == "cape"

    def test_cape_wannacry_family(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_cape.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            assert processed["family"].lower() in (
                "wanacry",
                "wannacry",
                "wannacryptor",
            )

    def test_cape_wannacry_ttps(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_cape.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            ttps = processed.get("ttps", [])
            assert len(ttps) >= 20
            # WannaCry encrypts files and destroys shadow copies
            assert "T1485" in ttps  # Data Destruction
            assert "T1059" in ttps  # Command and Scripting Interpreter

    def test_cape_wannacry_signatures(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_cape.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            sigs = processed.get("signatures", [])
            assert len(sigs) >= 30
            assert "encrypt_pcinfo" in sigs

    def test_cape_wannacry_network_ips(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_cape.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            ips = processed.get("ips", [])
            assert len(ips) >= 15
            # WannaCry contacts many IPs for worm propagation
            assert all(isinstance(ip, str) for ip in ips)

    def test_cape_wannacry_domains(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_cape.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            domains = processed.get("domains", [])
            assert len(domains) >= 1

    def test_cape_wannacry_has_all_expected_keys(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_cape.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            for key in (
                "provider",
                "family",
                "score",
                "ttps",
                "domains",
                "ips",
                "signatures",
                "sha256",
                "permalink",
                "summary",
            ):
                assert key in processed, f"Missing key: {key}"

    # ── Triage parsing — WannaCry ─────────────────────────────────────

    def test_triage_wannacry_provider_detected(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_triage.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "triage")
            processed = SandboxProcessor.process(task.json)
            assert processed is not None
            assert processed["provider"] == "triage"

    def test_triage_wannacry_family(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_triage.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "triage")
            processed = SandboxProcessor.process(task.json)
            assert "wannacry" in processed["family"].lower()

    def test_triage_wannacry_score(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_triage.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "triage")
            processed = SandboxProcessor.process(task.json)
            assert processed["score"] == 100
            assert processed["malscore"] == 100

    def test_triage_wannacry_ttps(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_triage.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "triage")
            processed = SandboxProcessor.process(task.json)
            ttps = processed.get("ttps", [])
            assert len(ttps) >= 5

    def test_triage_wannacry_signatures(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_triage.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "triage")
            processed = SandboxProcessor.process(task.json)
            sigs = processed.get("signatures", [])
            assert len(sigs) >= 10
            assert any("wannacry" in s.lower() for s in sigs)

    def test_triage_wannacry_ips(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_wannacry_triage.yaml"):
            task = api.sandbox_task_latest(WANNACRY_SHA256, "triage")
            processed = SandboxProcessor.process(task.json)
            ips = processed.get("ips", [])
            assert len(ips) >= 5

    # ── Cape parsing — Rhadamanthys ───────────────────────────────────

    def test_cape_rhadamanthys_parses(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_rhadamanthys_cape.yaml"):
            task = api.sandbox_task_latest(RHADAMANTHYS_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            assert processed is not None
            assert processed["provider"] == "cape"

    def test_cape_rhadamanthys_ttps(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_rhadamanthys_cape.yaml"):
            task = api.sandbox_task_latest(RHADAMANTHYS_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            ttps = processed.get("ttps", [])
            assert len(ttps) >= 3
            assert "T1027" in ttps  # Obfuscated Files

    def test_cape_rhadamanthys_network(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_rhadamanthys_cape.yaml"):
            task = api.sandbox_task_latest(RHADAMANTHYS_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            ips = processed.get("ips", [])
            assert len(ips) >= 5

    # ── Cape parsing — gh0stRAT/Pincav sample ─────────────────────────

    def test_cape_sample_provider(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_sample_cape.yaml"):
            task = api.sandbox_task_latest(SAMPLE_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            assert processed is not None
            assert processed["provider"] == "cape"

    def test_cape_sample_score(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_sample_cape.yaml"):
            task = api.sandbox_task_latest(SAMPLE_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            assert processed["malscore"] == 90

    def test_cape_sample_ttps(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_sample_cape.yaml"):
            task = api.sandbox_task_latest(SAMPLE_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            ttps = processed.get("ttps", [])
            assert len(ttps) >= 10
            assert "T1055" in ttps  # Process Injection
            assert "T1003" in ttps  # OS Credential Dumping
            assert "T1082" in ttps  # System Information Discovery
            assert "T1071" in ttps  # Application Layer Protocol

    def test_cape_sample_signatures(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_sample_cape.yaml"):
            task = api.sandbox_task_latest(SAMPLE_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            sigs = processed.get("signatures", [])
            assert len(sigs) >= 15

    def test_cape_sample_network(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_sample_cape.yaml"):
            task = api.sandbox_task_latest(SAMPLE_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            ips = processed.get("ips", [])
            domains = processed.get("domains", [])
            assert len(ips) >= 5
            assert len(domains) >= 1
            # Known C2 domain from sandbox
            domain_names = [d["domain"] if isinstance(d, dict) else d for d in domains]
            assert "wuoqmoaa.st" in domain_names

    def test_cape_sample_labels(self, api, vcr_instance):
        with vcr_instance.use_cassette("sandbox_latest_sample_cape.yaml"):
            task = api.sandbox_task_latest(SAMPLE_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)
            labels = processed.get("labels", [])
            assert len(labels) >= 10
            assert "injection" in labels
            assert "credential_dumping" in labels


# ── Sandbox Submission ────────────────────────────────────────────────────────


class TestSandboxSubmission:
    """Verify sandbox file submission from recorded interaction."""

    def test_submit_returns_task_id(self, api, vcr_instance):
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        with vcr_instance.use_cassette("sandbox_eicar_submit.yaml"):
            task = api.sandbox_file(
                io.BytesIO(eicar),
                artifact_name="eicar.com",
                provider_slug="cape",
                vm_slug="win-10-build-19041",
                network_enabled=False,
            )
            assert task.id is not None
            assert task.status in ("PENDING", "STARTED")


# ── Client Status Helpers ─────────────────────────────────────────────────────


class TestClientStatusHelpers:
    """Verify PolySwarmClient static status classification methods."""

    def test_success_states(self):
        assert PolySwarmClient.is_sandbox_success("SUCCESS")
        assert PolySwarmClient.is_sandbox_success("SUCCEEDED")
        assert PolySwarmClient.is_sandbox_success("succeeded")
        assert not PolySwarmClient.is_sandbox_success("PENDING")
        assert not PolySwarmClient.is_sandbox_success("FAILED")

    def test_failure_states(self):
        assert PolySwarmClient.is_sandbox_failure("FAILED")
        assert PolySwarmClient.is_sandbox_failure("TIMED OUT")
        assert PolySwarmClient.is_sandbox_failure("TIMEDOUT")
        assert PolySwarmClient.is_sandbox_failure("FAILED WITH QUOTA REIMBURSEMENT")
        assert PolySwarmClient.is_sandbox_failure("FAILED REIMBURSED")
        assert PolySwarmClient.is_sandbox_failure("TIMED OUT WITH QUOTA REIMBURSEMENT")
        assert PolySwarmClient.is_sandbox_failure("TIMEDOUT REIMBURSED")
        assert not PolySwarmClient.is_sandbox_failure("SUCCESS")
        assert not PolySwarmClient.is_sandbox_failure("PENDING")

    def test_terminal_states(self):
        assert PolySwarmClient.is_sandbox_terminal("SUCCESS")
        assert PolySwarmClient.is_sandbox_terminal("FAILED")
        assert not PolySwarmClient.is_sandbox_terminal("PENDING")
        assert not PolySwarmClient.is_sandbox_terminal("RUNNING")


# ── End-to-end: cassette data → SandboxProcessor → StixBuilder → STIX ────────


class TestVCRToSTIX:
    """Verify the full pipeline: real API data → parsed results → STIX objects.

    Exercises SandboxProcessor + StixBuilder with cassette-recorded data,
    ensuring report parsing code actually produces valid STIX output.
    """

    @pytest.fixture
    def builder(self, stub_helper):
        from connector.stix_builder import StixBuilder

        return StixBuilder(helper=stub_helper)

    @pytest.fixture
    def wannacry_entity(self):
        return {
            "type": "artifact",
            "spec_version": "2.1",
            "id": "artifact--00000000-0000-4000-8000-000000000001",
            "hashes": {"SHA-256": WANNACRY_SHA256},
        }

    def _build_stix(
        self,
        api,
        vcr_instance,
        builder,
        entity,
        scan_cassette,
        sandbox_cassette,
        sandbox_provider,
    ):
        """Helper: load cassette data, process, and build STIX bundle."""
        # Process scan
        scan_mapped = None
        if scan_cassette:
            with vcr_instance.use_cassette(scan_cassette):
                for result in api.search(WANNACRY_SHA256):
                    scan_mapped = ScanProcessor.process(result.json)
                    break

        # Process sandbox
        sandbox_processed = {}
        with vcr_instance.use_cassette(sandbox_cassette):
            task = api.sandbox_task_latest(WANNACRY_SHA256, sandbox_provider)
            processed = SandboxProcessor.process(task.json)
            if processed:
                sandbox_processed[sandbox_provider] = processed

        return builder.build_bundle(
            entity=entity,
            scan_data=scan_mapped,
            sandbox_data=processed,
            sandbox_results=sandbox_processed,
        )

    def test_wannacry_cape_produces_stix_objects(
        self, api, vcr_instance, builder, wannacry_entity
    ):
        stix_objects = self._build_stix(
            api,
            vcr_instance,
            builder,
            wannacry_entity,
            "hash_search_wannacry.yaml",
            "sandbox_latest_wannacry_cape.yaml",
            "cape",
        )
        assert len(stix_objects) > 0
        types = {obj.get("type") for obj in stix_objects}
        assert "identity" in types  # PolySwarm author
        assert "note" in types  # scan/sandbox notes

    def test_wannacry_cape_has_malware_object(
        self, api, vcr_instance, builder, wannacry_entity
    ):
        stix_objects = self._build_stix(
            api,
            vcr_instance,
            builder,
            wannacry_entity,
            "hash_search_wannacry.yaml",
            "sandbox_latest_wannacry_cape.yaml",
            "cape",
        )
        malware_objects = [o for o in stix_objects if o.get("type") == "malware"]
        assert len(malware_objects) >= 1
        families = [m.get("name", "").lower() for m in malware_objects]
        assert any(
            "wana" in f or "wannacry" in f for f in families
        ), f"Expected WannaCry family, got: {families}"

    def test_wannacry_cape_has_attack_patterns(
        self, api, vcr_instance, builder, wannacry_entity
    ):
        stix_objects = self._build_stix(
            api,
            vcr_instance,
            builder,
            wannacry_entity,
            None,
            "sandbox_latest_wannacry_cape.yaml",
            "cape",
        )
        attack_patterns = [o for o in stix_objects if o.get("type") == "attack-pattern"]
        assert (
            len(attack_patterns) >= 5
        ), f"Expected >=5 ATT&CK patterns, got {len(attack_patterns)}"
        # Check they have MITRE external references
        for ap in attack_patterns:
            ext_refs = ap.get("external_references", [])
            assert any(
                r.get("source_name") == "mitre-attack" for r in ext_refs
            ), f"Attack pattern {ap.get('name')} missing MITRE reference"

    def test_wannacry_cape_has_relationships(
        self, api, vcr_instance, builder, wannacry_entity
    ):
        stix_objects = self._build_stix(
            api,
            vcr_instance,
            builder,
            wannacry_entity,
            "hash_search_wannacry.yaml",
            "sandbox_latest_wannacry_cape.yaml",
            "cape",
        )
        relationships = [o for o in stix_objects if o.get("type") == "relationship"]
        assert len(relationships) >= 5
        rel_types = {r.get("relationship_type") for r in relationships}
        assert "uses" in rel_types or "related-to" in rel_types

    def test_wannacry_cape_has_indicator(
        self, api, vcr_instance, builder, wannacry_entity
    ):
        stix_objects = self._build_stix(
            api,
            vcr_instance,
            builder,
            wannacry_entity,
            "hash_search_wannacry.yaml",
            "sandbox_latest_wannacry_cape.yaml",
            "cape",
        )
        indicators = [o for o in stix_objects if o.get("type") == "indicator"]
        assert len(indicators) >= 1
        # Should contain the SHA-256 hash in the pattern
        patterns = [i.get("pattern", "") for i in indicators]
        assert any(WANNACRY_SHA256 in p for p in patterns)

    def test_wannacry_cape_has_network_observables(
        self, api, vcr_instance, builder, wannacry_entity
    ):
        stix_objects = self._build_stix(
            api,
            vcr_instance,
            builder,
            wannacry_entity,
            None,
            "sandbox_latest_wannacry_cape.yaml",
            "cape",
        )
        ip_objects = [o for o in stix_objects if o.get("type") == "ipv4-addr"]
        # WannaCry has 19 IPs and 1 domain in Cape sandbox
        assert (
            len(ip_objects) >= 5
        ), f"Expected >=5 IP observables, got {len(ip_objects)}"

    def test_wannacry_triage_produces_stix(
        self, api, vcr_instance, builder, wannacry_entity
    ):
        stix_objects = self._build_stix(
            api,
            vcr_instance,
            builder,
            wannacry_entity,
            None,
            "sandbox_latest_wannacry_triage.yaml",
            "triage",
        )
        assert len(stix_objects) > 0
        types = {obj.get("type") for obj in stix_objects}
        assert "identity" in types
        assert "malware" in types
        assert "note" in types

    def test_stix_ids_are_deterministic(
        self, api, vcr_instance, builder, wannacry_entity
    ):
        """Running the same data twice should produce identical STIX IDs."""
        objs1 = self._build_stix(
            api,
            vcr_instance,
            builder,
            wannacry_entity,
            "hash_search_wannacry.yaml",
            "sandbox_latest_wannacry_cape.yaml",
            "cape",
        )
        objs2 = self._build_stix(
            api,
            vcr_instance,
            builder,
            wannacry_entity,
            "hash_search_wannacry.yaml",
            "sandbox_latest_wannacry_cape.yaml",
            "cape",
        )
        ids1 = sorted(o.get("id", "") for o in objs1 if o.get("id"))
        ids2 = sorted(o.get("id", "") for o in objs2 if o.get("id"))
        assert ids1 == ids2, "STIX IDs should be deterministic across runs"

    def test_sample_cape_produces_stix_with_network(self, api, vcr_instance, builder):
        """gh0stRAT/Pincav sample: verify C2 domain and IPs become STIX observables."""
        entity = {
            "type": "artifact",
            "spec_version": "2.1",
            "id": "artifact--00000000-0000-4000-8000-000000000002",
            "hashes": {"SHA-256": SAMPLE_SHA256},
        }
        with vcr_instance.use_cassette("sandbox_latest_sample_cape.yaml"):
            task = api.sandbox_task_latest(SAMPLE_SHA256, "cape")
            processed = SandboxProcessor.process(task.json)

        stix_objects = builder.build_bundle(
            entity=entity,
            sandbox_data=processed,
            sandbox_results={"cape": processed},
        )
        types = {obj.get("type") for obj in stix_objects}
        assert "ipv4-addr" in types
        assert "domain-name" in types
        # The C2 domain should be present
        domains = [o for o in stix_objects if o.get("type") == "domain-name"]
        domain_values = [d.get("value") for d in domains]
        assert "wuoqmoaa.st" in domain_values
        # ATT&CK patterns from the 12 TTPs
        attack_patterns = [o for o in stix_objects if o.get("type") == "attack-pattern"]
        assert len(attack_patterns) >= 5

    def test_all_objects_have_valid_types(
        self, api, vcr_instance, builder, wannacry_entity
    ):
        stix_objects = self._build_stix(
            api,
            vcr_instance,
            builder,
            wannacry_entity,
            "hash_search_wannacry.yaml",
            "sandbox_latest_wannacry_cape.yaml",
            "cape",
        )
        valid_types = {
            "identity",
            "malware",
            "indicator",
            "note",
            "relationship",
            "attack-pattern",
            "ipv4-addr",
            "ipv6-addr",
            "domain-name",
            "url",
            "threat-actor",
            "intrusion-set",
            "vulnerability",
            "location",
            "campaign",
            "tool",
            "artifact",
            "file",
            "marking-definition",
            "report",
        }
        for obj in stix_objects:
            assert (
                obj.get("type") in valid_types
            ), f"Invalid STIX type: {obj.get('type')}"
