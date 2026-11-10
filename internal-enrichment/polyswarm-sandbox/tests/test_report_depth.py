"""Tests for report depth: dropped files, configured C2, pcap.

Report shapes are taken from real PolySwarm sandbox tasks (read only): CAPE
``report.dropped[]``, Triage ``report.dumped[]`` and
``report.extracted[].config.c2``, and ``sandbox_artifacts[]``.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from connector.polyswarm_client import PolySwarmClient
from connector.report_depth import (
    _classify_c2,
    build_report_depth_objects,
    extract_report_depth,
    select_pcap_artifact,
)
from connector.sandbox_processor import SandboxProcessor
from connector.stix_builder import StixBuilder
from stix2validator import ValidationOptions, validate_string

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

SAMPLE_SHA = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
DROP_A = "e1056f0320750177fdd83d1b1e65985dc814593300aa340b7b29d3fefb35da2f"
DROP_B = "8dc05b49910dc21791cafc0e0774e23a962ab499109c961304a6e77e4ba19f34"
DROP_C = "a5d95d381321afc4d15a69309b94f164bb1fe37586a1c49ff096f55f71576bc7"

ENTITY = {
    "type": "file",
    "spec_version": "2.1",
    "id": "file--00000000-0000-4000-8000-000000000001",
    "hashes": {"SHA-256": SAMPLE_SHA},
}
URL_ENTITY = {
    "type": "url",
    "spec_version": "2.1",
    "id": "url--00000000-0000-4000-8000-000000000002",
    "value": "http://malware.example/x",
}


def _cape_task():
    return {
        "sandbox": "cape",
        "sha256": SAMPLE_SHA,
        "status": "SUCCEEDED",
        "config": {"cape_malscore": 9.0},
        "report": {
            "malscore": 9.0,
            "malware_family": ["WannaCry"],
            "signature_names": ["x"],
            "dropped": [
                {
                    "name": ["1017.WNCRYT"],
                    "size": 2105344,
                    "type": "Extensible storage engine DataBase, version 0x620",
                    "sha256": DROP_A,
                    "md5": "f128d7bbb55246bcbd50f21f53f30cbc",
                    "sha1": "c1da02c71f53ab4fbb78941b1b714c3d1f7b4223",
                    "guest_paths": [
                        "C:\\Users\\maxine\\AppData\\Local\\Temp\\1017.WNCRYT"
                    ],
                },
                {
                    "name": [],
                    "size": 297,
                    "sha256": DROP_B.upper(),
                    "guest_paths": [
                        "C:\\Users\\maxine\\AppData\\Local\\Temp\\1156.WNCRYT"
                    ],
                },
                {"name": ["dup"], "sha256": DROP_A},
                {"name": ["self"], "sha256": SAMPLE_SHA},
                {"name": ["bad"], "sha256": "not-a-hash"},
                {"name": ["nohash"]},
                "garbage",
            ],
        },
        "sandbox_artifacts": [
            {
                "type": "dropped_file",
                "name": DROP_A,
                "mimetype": "application/x-sqlite3",
            },
            {"type": "dropped_file", "name": DROP_B, "mimetype": ""},
            {"type": "pcap", "name": "cape_pcap-3.pcap", "instance_id": "111"},
            {"type": "pcap", "name": "cape_pcap-2.pcap", "instance_id": "222"},
        ],
    }


def _triage_task():
    return {
        "sandbox": "triage",
        "sha256": SAMPLE_SHA,
        "status": "SUCCEEDED",
        "config": {"traige_analysis_score": 9, "triage_static_score": 5},
        "report": {
            "targets": [{"score": 9, "tags": [], "signatures": [], "iocs": {}}],
            "malware_family": ["xworm"],
            "extracted": [
                {
                    "resource": "behavioral1/memory/1.dmp",
                    "config": {
                        "family": "xworm",
                        "rule": "Xworm",
                        "version": "5.0",
                        "c2": [
                            "147.185.221.23:48450",
                            "bore.pub:55435",
                            "vte.duckdns.org",
                            "https://c2.example.net/gate.php?id=1",
                            "10.0.0.5:80",
                            "not a host",
                            "bore.pub:55435",
                        ],
                    },
                },
                {"config": {"family": "havoc", "rule": "Havoc", "attr": {}}},
                {"ransom_note": {"family": "wannacry"}},
            ],
            "dumped": [
                {
                    "kind": "martian",
                    "name": "files/0x0001000000025951-4.dat",
                    "path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\drop.exe",
                    "sha256": DROP_C,
                    "md5": "1f75669506cef107d86080eae0d9047c",
                    "sha1": "1145830be9ff52e617b154d2cc124fb541b8d574",
                    "size": 152,
                }
            ],
            "extracted_c2_ips": ["147.185.221.23"],
        },
        "sandbox_artifacts": [],
    }


# --- extraction ---


class TestExtractDropped:
    def test_cape_dropped_files(self):
        depth = extract_report_depth(_cape_task())
        files = {f["sha256"]: f for f in depth["dropped_files"]}
        assert set(files) == {DROP_A, DROP_B}
        a = files[DROP_A]
        assert a["name"] == "1017.WNCRYT"
        assert a["size"] == 2105344
        assert a["md5"] == "f128d7bbb55246bcbd50f21f53f30cbc"
        assert a["mime_type"] == "application/x-sqlite3"

    def test_uppercase_hash_lowercased_name_from_guest_path(self):
        files = {
            f["sha256"]: f for f in extract_report_depth(_cape_task())["dropped_files"]
        }
        assert files[DROP_B]["name"] == "1156.WNCRYT"
        assert "mime_type" not in files[DROP_B]  # empty mimetype is not invented

    def test_sample_itself_and_invalid_hashes_skipped(self):
        shas = [
            f["sha256"] for f in extract_report_depth(_cape_task())["dropped_files"]
        ]
        assert SAMPLE_SHA not in shas
        assert len(shas) == len(set(shas))

    def test_triage_dumped_uses_path_basename_not_resource_name(self):
        depth = extract_report_depth(_triage_task())
        (f,) = depth["dropped_files"]
        assert f["sha256"] == DROP_C
        assert f["name"] == "drop.exe"

    def test_triage_dumped_without_path_has_no_name(self):
        task = _triage_task()
        del task["report"]["dumped"][0]["path"]
        (f,) = extract_report_depth(task)["dropped_files"]
        assert "name" not in f

    def test_recorded_url_task_fixture(self):
        with open(os.path.join(FIXTURES, "sandbox_url_task_triage.json")) as fh:
            task = json.load(fh)
        depth = extract_report_depth(task)
        dumped = task["report"]["dumped"]
        assert len(depth["dropped_files"]) == len({d["sha256"] for d in dumped})
        assert depth["c2"] == []

    @pytest.mark.parametrize(
        "raw",
        [None, {}, {"report": None}, {"report": []}, {"report": {"dropped": "x"}}],
    )
    def test_odd_input_is_safe(self, raw):
        assert extract_report_depth(raw) == {"dropped_files": [], "c2": []}


class TestExtractC2:
    def test_config_c2_classified(self):
        c2 = extract_report_depth(_triage_task())["c2"]
        got = {(c["type"], c["value"]): c for c in c2}
        assert ("ipv4-addr", "147.185.221.23") in got
        assert got[("ipv4-addr", "147.185.221.23")]["port"] == 48450
        assert ("domain-name", "bore.pub") in got
        assert ("domain-name", "vte.duckdns.org") in got
        assert ("url", "https://c2.example.net/gate.php?id=1") in got
        assert got[("domain-name", "bore.pub")]["family"] == "xworm"
        assert got[("domain-name", "bore.pub")]["provider"] == "triage"

    def test_private_ip_garbage_and_duplicates_dropped(self):
        c2 = extract_report_depth(_triage_task())["c2"]
        values = [c["value"] for c in c2]
        assert "10.0.0.5" not in values
        assert not any("not a host" in v for v in values)
        assert values.count("bore.pub") == 1

    def test_config_without_c2_gives_nothing(self):
        task = _triage_task()
        task["report"]["extracted"] = [{"config": {"family": "havoc", "rule": "Havoc"}}]
        assert extract_report_depth(task)["c2"] == []

    def test_cape_has_no_configured_c2(self):
        assert extract_report_depth(_cape_task())["c2"] == []

    def test_suricata_candidates_are_not_configured_c2(self):
        task = _cape_task()
        task["report"]["suricata"] = {"alerts": [{"signature": "ET MALWARE CnC"}]}
        assert extract_report_depth(task)["c2"] == []

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("8.8.4.4:53", ("ipv4-addr", "8.8.4.4", 53)),
            ("[2001:4860:4860::8888]:443", ("ipv6-addr", "2001:4860:4860::8888", 443)),
            ("Evil.Example.COM.", ("domain-name", "evil.example.com", None)),
            ("ftp://x.example.org/a", ("url", "ftp://x.example.org/a", None)),
        ],
    )
    def test_classify(self, text, expected):
        c = _classify_c2(text)
        assert (c["type"], c["value"], c.get("port")) == expected

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "   ",
            "127.0.0.1",
            "host:99999",
            "host:abc",
            "javascript://x",
            "a b",
            "[::1",
        ],
    )
    def test_classify_rejects(self, text):
        assert _classify_c2(text) is None

    def test_pcap_selection(self):
        assert select_pcap_artifact(_cape_task())["instance_id"] == "111"
        assert select_pcap_artifact(_triage_task()) is None
        assert select_pcap_artifact(None) is None


# --- processor hook ---


class TestProcessorHook:
    def test_process_adds_report_depth(self):
        for task in (_cape_task(), _triage_task()):
            out = SandboxProcessor.process(task)
            assert set(out["report_depth"]) == {"dropped_files", "c2"}

    def test_hostname_c2_no_longer_an_ip_candidate(self):
        out = SandboxProcessor.process(_triage_task())
        ips = [c["ip"] for c in out["c2_candidates"]]
        assert "bore.pub" not in ips and "vte.duckdns.org" not in ips
        assert "147.185.221.23" in ips


# --- STIX objects ---


@pytest.fixture
def builder(stub_helper):
    return StixBuilder(helper=stub_helper)


def _depths():
    return [
        extract_report_depth(_cape_task()),
        extract_report_depth(_triage_task()),
    ]


def _build(builder, entity=ENTITY, malware_id=None, **kw):
    args = {
        "max_dropped_files": 25,
        "create_observables": True,
        "c2_indicators": True,
        "create_indicators": True,
    }
    args.update(kw)
    return build_report_depth_objects(builder, entity, malware_id, _depths(), **args)


def _of(objs, t):
    return [o for o in objs if o["type"] == t]


def _dropped(objs):
    return [o for o in _of(objs, "file") if o["id"] != ENTITY["id"]]


class TestObjects:
    def test_file_observables_and_related_to(self, builder):
        objs = _build(builder)
        files = _of(objs, "file")
        assert {f["hashes"]["SHA-256"] for f in files} == {DROP_A, DROP_B, DROP_C}
        a = next(f for f in files if f["hashes"]["SHA-256"] == DROP_A)
        assert a["name"] == "1017.WNCRYT"
        assert a["size"] == 2105344
        assert a["mime_type"] == "application/x-sqlite3"
        assert a["hashes"]["MD5"] == "f128d7bbb55246bcbd50f21f53f30cbc"
        rels = [
            r
            for r in _of(objs, "relationship")
            if r["target_ref"] in {f["id"] for f in files}
        ]
        assert len(rels) == 3
        assert {r["relationship_type"] for r in rels} == {"related-to"}
        assert {r["source_ref"] for r in rels} == {ENTITY["id"]}

    def test_file_ids_deterministic_and_hash_only(self, builder):
        ids1 = {f["id"] for f in _of(_build(builder), "file")}
        ids2 = {f["id"] for f in _of(_build(builder), "file")}
        assert ids1 == ids2

    def test_no_malware_drops_relationship_by_default(self, builder):
        objs = _build(
            builder, malware_id="malware--00000000-0000-4000-8000-000000000009"
        )
        assert "drops" not in {
            r["relationship_type"] for r in _of(objs, "relationship")
        }

    def test_malware_drops_when_enabled(self, builder, monkeypatch):
        monkeypatch.setattr("connector.report_depth.MALWARE_DROPS_FILE", True)
        mid = "malware--00000000-0000-4000-8000-000000000009"
        objs = _build(builder, malware_id=mid)
        drops = [
            r for r in _of(objs, "relationship") if r["relationship_type"] == "drops"
        ]
        assert len(drops) == 3 and {d["source_ref"] for d in drops} == {mid}

    def test_cap_limits_files(self, builder):
        assert len(_of(_build(builder, max_dropped_files=2), "file")) == 2

    def test_zero_turns_dropped_files_off_but_keeps_c2(self, builder):
        objs = _build(builder, max_dropped_files=0)
        assert _of(objs, "file") == []
        assert _of(objs, "domain-name")

    def test_observables_off_means_nothing(self, builder):
        assert _build(builder, create_observables=False) == []

    def test_c2_observables_related_to_sample(self, builder):
        objs = _build(builder)
        by_type = {t: _of(objs, t) for t in ("ipv4-addr", "domain-name", "url")}
        assert {o["value"] for o in by_type["ipv4-addr"]} == {"147.185.221.23"}
        assert {o["value"] for o in by_type["domain-name"]} == {
            "bore.pub",
            "vte.duckdns.org",
        }
        assert len(by_type["url"]) == 1
        ids = {o["id"] for ts in by_type.values() for o in ts}
        rels = [r for r in _of(objs, "relationship") if r["target_ref"] in ids]
        assert {
            r["source_ref"] for r in rels if r["relationship_type"] == "related-to"
        } == {ENTITY["id"]}

    def test_url_entity_never_communicates_with(self, builder):
        objs = _build(builder, entity=URL_ENTITY)
        sources = {
            r["relationship_type"]
            for r in _of(objs, "relationship")
            if r["source_ref"] == URL_ENTITY["id"]
        }
        assert sources == {"related-to"}

    def test_url_c2_has_no_malware_communicates_with(self, builder):
        mid = "malware--00000000-0000-4000-8000-000000000009"
        objs = _build(builder, malware_id=mid)
        url_id = _of(objs, "url")[0]["id"]
        assert not [
            r
            for r in _of(objs, "relationship")
            if r["source_ref"] == mid and r["target_ref"] == url_id
        ]
        ip_id = _of(objs, "ipv4-addr")[0]["id"]
        assert [
            r
            for r in _of(objs, "relationship")
            if r["source_ref"] == mid
            and r["target_ref"] == ip_id
            and r["relationship_type"] == "communicates-with"
        ]

    def test_c2_indicators(self, builder):
        mid = "malware--00000000-0000-4000-8000-000000000009"
        objs = _build(builder, malware_id=mid)
        inds = _of(objs, "indicator")
        assert len(inds) == 4
        ip = next(i for i in inds if i["name"] == "147.185.221.23")
        assert ip["pattern"] == "[ipv4-addr:value = '147.185.221.23']"
        assert ip["x_opencti_main_observable_type"] == "IPv4-Addr"
        assert "extracted by the PolySwarm sandbox" in ip["description"]
        assert "configuration" in ip["description"]
        from datetime import datetime

        vf = datetime.fromisoformat(ip["valid_from"].replace("Z", "+00:00"))
        vu = datetime.fromisoformat(ip["valid_until"].replace("Z", "+00:00"))
        assert (vu - vf).days == 30
        kinds = {
            r["relationship_type"]
            for r in _of(objs, "relationship")
            if r["source_ref"] == ip["id"]
        }
        assert kinds == {"based-on", "indicates"}

    def test_url_indicator_pattern_escapes_quote(self, builder):
        depth = {
            "dropped_files": [],
            "c2": [{"type": "url", "value": "http://x.example/a'b"}],
        }
        objs = build_report_depth_objects(
            builder,
            ENTITY,
            None,
            [depth],
            max_dropped_files=0,
            create_observables=True,
            c2_indicators=True,
            create_indicators=True,
        )
        assert _of(objs, "indicator")[0]["pattern"] == (
            "[url:value = 'http://x.example/a\\'b']"
        )

    def test_indicators_off_by_setting(self, builder):
        objs = _build(builder, c2_indicators=False)
        assert _of(objs, "indicator") == []
        assert _of(objs, "domain-name")

    def test_indicators_off_when_create_indicators_off(self, builder):
        assert _of(_build(builder, create_indicators=False), "indicator") == []

    def test_bundle_validates_as_stix(self, builder):
        objs = [builder.author] + _build(
            builder, malware_id="malware--00000000-0000-4000-8000-000000000009"
        )
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-0000000000aa",
            "objects": objs,
        }
        res = validate_string(
            json.dumps(bundle), ValidationOptions(strict=False, version="2.1")
        )
        errors = [e for e in res.errors]
        assert not errors, errors


class TestBuildBundleHook:
    CONFIG = {
        "create_indicators": True,
        "create_observables": True,
        "min_polyscore": 50,
        "sandbox_max_dropped_files": 25,
        "sandbox_c2_indicators": True,
    }

    def _bundle(self, builder, config):
        results = {
            "triage": SandboxProcessor.process(_triage_task()),
            "cape": SandboxProcessor.process(_cape_task()),
        }
        return builder.build_bundle(
            entity=ENTITY, sandbox_results=results, config=config
        )

    def test_bundle_contains_depth_objects(self, builder):
        objs = self._bundle(builder, self.CONFIG)
        assert len(_dropped(objs)) == 3
        assert any(o["type"] == "indicator" and o["name"] == "bore.pub" for o in objs)

    def test_relationships_sorted_after_objects(self, builder):
        objs = self._bundle(builder, self.CONFIG)
        first_rel = next(i for i, o in enumerate(objs) if o["type"] == "relationship")
        assert all(o["type"] == "relationship" for o in objs[first_rel:])

    def test_settings_respected(self, builder):
        cfg = dict(
            self.CONFIG, sandbox_max_dropped_files=0, sandbox_c2_indicators=False
        )
        objs = self._bundle(builder, cfg)
        assert _dropped(objs) == []
        assert not [o for o in _of(objs, "indicator") if o["name"] == "bore.pub"]

    def test_legacy_result_without_depth_is_fine(self, builder):
        objs = builder.build_bundle(
            entity=ENTITY,
            sandbox_results={"triage": {"provider": "triage", "score": 90}},
            config=self.CONFIG,
        )
        assert _dropped(objs) == []


# --- settings ---


class TestSettings:
    def test_defaults(self):
        from connector.models.configs.settings import PolySwarmConfig

        cfg = PolySwarmConfig(api_key="k")
        assert cfg.sandbox_max_dropped_files == 25
        assert cfg.sandbox_c2_indicators is True
        assert cfg.sandbox_attach_pcap is False
        assert cfg.sandbox_pcap_max_size == 26214400

    def test_negative_dropped_files_rejected(self):
        from connector.models.configs.settings import PolySwarmConfig
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            PolySwarmConfig(api_key="k", sandbox_max_dropped_files=-1)


# --- pcap ---


def _client():
    c = PolySwarmClient.__new__(PolySwarmClient)
    c.helper = MagicMock()
    c.api = MagicMock()
    c._breaker = MagicMock()
    c._breaker.allow_request.return_value = True
    return c


class TestPcapDownload:
    def _fake_download(self, payload, name="cape_pcap-3.pcap"):
        def _dl(folder, task_id, instance_id):
            with open(os.path.join(folder, name), "wb") as fh:
                fh.write(payload)
            return MagicMock()

        return _dl

    def test_returns_name_and_bytes(self):
        c = _client()
        c.api.download_sandbox_artifact.side_effect = self._fake_download(
            b"\xd4\xc3\xb2\xa1"
        )
        assert c.download_sandbox_artifact_bytes("t", "111", 1000) == (
            "cape_pcap-3.pcap",
            b"\xd4\xc3\xb2\xa1",
        )
        assert c.api.download_sandbox_artifact.call_args.args[1:] == ("t", "111")

    def test_over_cap_skipped(self):
        c = _client()
        c.api.download_sandbox_artifact.side_effect = self._fake_download(b"x" * 11)
        assert c.download_sandbox_artifact_bytes("t", "111", 10) is None

    def test_failure_returns_none(self):
        c = _client()
        c.api.download_sandbox_artifact.side_effect = ValueError("boom")
        with patch("time.sleep"):
            assert c.download_sandbox_artifact_bytes("t", "111", 10) is None


class TestPcapAttach:
    def _connector(self, **over):
        from tests.test_connector import make_connector

        return make_connector(polyswarm_overrides=dict(over))

    def _phase(self, c, results):
        return c._phase_reports(
            entity={"id": "file--test"},
            scan_id=None,
            scan_res=None,
            scan_mapped=None,
            sandbox_tasks={"cape": "task-1"},
            sandbox_results=results,
            llm_task_ids={},
            filename="x.exe",
            lookup_hash="ab" * 32,
        )

    BASE = {
        "json_report_enabled": False,
        "pdf_report_enabled": False,
        "llm_report_enabled": False,
    }

    def test_off_by_default_no_download(self):
        c = self._connector(**self.BASE, sandbox_attach_pcap=False)
        self._phase(c, {"cape": _cape_task()})
        c.polyswarm_client.download_sandbox_artifact_bytes.assert_not_called()

    def test_on_attaches_pcap(self):
        c = self._connector(
            **self.BASE, sandbox_attach_pcap=True, sandbox_pcap_max_size=5000
        )
        c.polyswarm_client.download_sandbox_artifact_bytes.return_value = (
            "cape_pcap-3.pcap",
            b"PCAP",
        )
        self._phase(c, {"cape": _cape_task()})
        c.polyswarm_client.download_sandbox_artifact_bytes.assert_called_once_with(
            "task-1", "111", 5000
        )
        kw = c.helper.api.stix_cyber_observable.add_file.call_args.kwargs
        assert kw["file_name"] == f"Sandbox_cape_{'ab' * 8}.pcap"
        assert kw["data"] == b"PCAP"

    def test_no_pcap_artifact_no_download(self):
        c = self._connector(**self.BASE, sandbox_attach_pcap=True)
        self._phase(c, {"cape": _triage_task()})
        c.polyswarm_client.download_sandbox_artifact_bytes.assert_not_called()

    def test_failed_download_attaches_nothing(self):
        c = self._connector(**self.BASE, sandbox_attach_pcap=True)
        c.polyswarm_client.download_sandbox_artifact_bytes.return_value = None
        self._phase(c, {"cape": _cape_task()})
        c.helper.api.stix_cyber_observable.add_file.assert_not_called()


# --- review fixes ---


class TestReviewFixes:
    @pytest.mark.parametrize(
        "text",
        [
            "http://192.168.1.5/gate.php",
            "http://localhost/x",
            "https://127.0.0.1:8080/a",
            "http://router.local/a",
            "http://intranet/a",
            "http://[::1]/a",
        ],
    )
    def test_internal_url_c2_rejected(self, text):
        assert _classify_c2(text) is None

    def test_public_url_c2_kept(self):
        assert _classify_c2("http://93.184.216.34/gate.php")["type"] == "url"

    @pytest.mark.parametrize(
        "value,kind",
        [
            ("api.telegram.org", "domain-name"),
            ("cdn.discordapp.com", "domain-name"),
            ("ngrok-free.app", "domain-name"),
            ("https://raw.githubusercontent.com/", "url"),
            ("https://pastebin.com", "url"),
        ],
    )
    def test_shared_service_keeps_observable_skips_indicator(
        self, builder, value, kind
    ):
        objs = _only_c2(builder, kind, value)
        assert _of(objs, kind)
        assert _of(objs, "indicator") == []

    def test_lookalike_domain_still_gets_indicator(self, builder):
        objs = _only_c2(builder, "domain-name", "notgithub.com")
        assert len(_of(objs, "indicator")) == 1

    def test_file_id_is_standard_stix2_id(self, builder):
        import stix2

        f = next(
            f for f in _of(_build(builder), "file") if f.get("name") == "1017.WNCRYT"
        )
        expected = stix2.File(
            hashes=f["hashes"], name=f["name"], size=f["size"], mime_type=f["mime_type"]
        )
        assert f["id"] == expected.id

    def test_markings_applied_to_every_object(self, builder):
        tlp = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
        entity = dict(ENTITY, objectMarking=[{"standard_id": tlp}])
        objs = _build(builder, entity=entity)
        assert objs
        assert all(o["object_marking_refs"] == [tlp] for o in objs)

    def test_stix_marking_refs_used_too(self, builder):
        tlp = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
        objs = _build(builder, entity=dict(ENTITY, object_marking_refs=[tlp]))
        assert all(o["object_marking_refs"] == [tlp] for o in objs)

    def test_no_markings_means_none_added(self, builder):
        assert all("object_marking_refs" not in o for o in _build(builder))

    def test_pcap_failure_log_has_no_exception_text(self):
        c = _client()
        c.api.download_sandbox_artifact.side_effect = ValueError("https://s3/secret")
        c.download_sandbox_artifact_bytes("t", "1", 10)
        logged = str(c.helper.connector_logger.warning.call_args)
        assert "secret" not in logged and "ValueError" in logged


def _only_c2(builder, kind, value):
    depth = {"dropped_files": [], "c2": [{"type": kind, "value": value}]}
    return build_report_depth_objects(
        builder,
        ENTITY,
        None,
        [depth],
        max_dropped_files=0,
        create_observables=True,
        c2_indicators=True,
        create_indicators=True,
    )


class TestRereview:
    @pytest.mark.parametrize(
        "text", ["dc01.corp:443", "c2.local", "srv.internal", "nas.lan:80", "intranet"]
    )
    def test_internal_bare_hosts_rejected(self, text):
        assert _classify_c2(text) is None

    def test_tunnel_subdomain_keeps_indicator(self, builder):
        for host in ("abc123.ngrok-free.app", "x.ngrok.io"):
            assert len(_of(_only_c2(builder, "domain-name", host), "indicator")) == 1

    def test_other_service_subdomain_still_suppressed(self, builder):
        objs = _only_c2(builder, "domain-name", "cdn.discordapp.com")
        assert _of(objs, "indicator") == []

    @pytest.mark.parametrize(
        "url",
        [
            "https://discord.com/api/webhooks/123/abc",
            "https://storage.googleapis.com/bucket/object.bin",
            "https://raw.githubusercontent.com/u/r/main/payload.txt",
            "https://api.telegram.org/bot123:ABC/sendMessage",
            "https://docs.google.com/uc?id=abc",
        ],
    )
    def test_specific_url_keeps_indicator(self, builder, url):
        objs = _only_c2(builder, "url", url)
        assert len(_of(objs, "indicator")) == 1
        assert _of(objs, "url")

    def test_bare_service_url_suppressed(self, builder):
        assert _of(_only_c2(builder, "url", "https://discord.com/"), "indicator") == []
        assert _of(_only_c2(builder, "url", "https://discord.com"), "indicator") == []
        q = _only_c2(builder, "url", "https://discord.com/?x=1")
        assert len(_of(q, "indicator")) == 1
