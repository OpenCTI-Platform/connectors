"""Tests for YARA hunting from OpenCTI Indicators.

Hunt shapes follow the SDK resource classes (HistoricalHunt,
HistoricalHuntResult) and a read-only listing of existing hunts on
2026-11-10: status PENDING / COMPLETED / LIMITED, progress, summary
{"count": N, "rule": {...}}, ruleset_name, window_days (null when no window
was requested). Nothing here creates a hunt: the SDK create call is mocked.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from conftest import StubHelper
from polyswarm_enrichment import yara_hunt
from polyswarm_enrichment.connector import ConnectorTemplate
from polyswarm_enrichment.converter_to_stix import ConverterToStix
from polyswarm_enrichment.polyswarm_client import polyswarm_exceptions
from polyswarm_enrichment.yara_hunt import (
    HuntOutcome,
    YaraHunter,
    build_file_objects,
    build_note,
    format_matched_strings,
    is_yara_indicator,
    rule_digest,
    rule_names,
    validate_rule,
)

RULE = 'rule demo_rule { strings: $a = "evil" condition: $a }'
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
IND_ID = "indicator--0d6a4c5e-4a2b-4c3d-9e8f-123456789abc"
TLP_CLEAR = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
TLP_GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"


class FakeHelper(StubHelper):
    def __init__(self):
        super().__init__()
        self.state = {}

    def get_state(self):
        return dict(self.state)

    def set_state(self, state):
        self.state = dict(state)


def _hunt(hunt_id="111", status="PENDING", count=None, name=None, **extra):
    data = {
        "id": hunt_id,
        "status": status,
        "progress": 100.0 if status in ("COMPLETED", "LIMITED") else 10.0,
        "summary": {"count": count, "rule": {}} if count is not None else None,
        "ruleset_name": name,
        "window_days": 30,
        "created": datetime.now(timezone.utc).isoformat(),
    }
    data.update(extra)
    return SimpleNamespace(json=data, **data)


def _result(sha, matched=None, rid=None):
    return SimpleNamespace(
        id=rid or f"r{sha[:2]}",
        sha256=sha,
        md5="d" * 32,
        sha1="e" * 40,
        rule_name="demo_rule",
        matched_strings=matched,
    )


class Clock:
    """Monotonic clock that advances only when the test sleeps."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _hunter(api, timeout=1800, max_results=50, helper=None):
    clock = Clock()
    return YaraHunter(
        api,
        helper or FakeHelper(),
        window_days=30,
        timeout=timeout,
        max_results=max_results,
        sleep=clock.sleep,
        clock=clock,
    )


def _api():
    api = MagicMock()
    api.community = "default"
    api.historical_list.return_value = iter([])
    return api


# ===========================================================================
# Helpers
# ===========================================================================
class TestHelpers:
    def test_is_yara_indicator(self):
        assert is_yara_indicator({"pattern_type": "yara", "pattern": RULE})
        assert is_yara_indicator({"pattern_type": "YARA", "pattern": RULE})
        assert not is_yara_indicator({"pattern_type": "stix", "pattern": "[a:b='c']"})
        assert not is_yara_indicator({"pattern_type": "yara", "pattern": "  "})
        assert not is_yara_indicator({})

    def test_rule_names(self):
        text = "private rule a1 { condition: true }\nglobal rule b2 { condition: true }"
        assert rule_names(text) == ["a1", "b2"]

    def test_digest_ignores_edge_whitespace(self):
        assert rule_digest(RULE) == rule_digest(f"\n{RULE}\n")

    def test_validate_without_library_defers_to_polyswarm(self):
        with patch.object(yara_hunt, "_yara", None):
            assert validate_rule("not a rule at all") is None

    def test_validate_with_library_reports_error(self):
        fake = MagicMock()
        fake.compile.side_effect = Exception("line 1: syntax error")
        with patch.object(yara_hunt, "_yara", fake):
            assert "syntax error" in validate_rule("bad")

    def test_validate_with_library_accepts_good_rule(self):
        with patch.object(yara_hunt, "_yara", MagicMock()):
            assert validate_rule(RULE) is None

    def test_matched_strings_are_short_ascii(self):
        item = {
            "offset": 69,
            "identifier": "$u",
            "data": "test_live\x00\xff" + "x" * 200,
        }
        lines = format_matched_strings([item] * 9)
        assert len(lines) == yara_hunt.STRINGS_PER_RESULT
        assert lines[0].startswith("$u at offset 69: test_live..")
        assert all(line.isascii() and len(line) < 140 for line in lines)

    def test_short_error_is_type_plus_short_ascii_message(self):
        err = ValueError("x" * 500 + "\u00e9\n" + "y")
        text = yara_hunt.short_error(err)
        assert text.startswith("ValueError: ") and len(text) < 140
        assert text.isascii() and "\n" not in text

    def test_hunt_name_is_stable_per_rule(self):
        assert YaraHunter.hunt_name(RULE) == YaraHunter.hunt_name(f" {RULE} ")
        assert YaraHunter.hunt_name(RULE).startswith("OpenCTI demo_rule ")


# ===========================================================================
# Hunt lifecycle
# ===========================================================================
class TestHunter:
    def test_starts_hunt_polls_and_reads_results(self):
        api = _api()
        api.historical_get.side_effect = [
            _hunt(status="PENDING"),
            _hunt(status="COMPLETED", count=2),
        ]
        api.historical_results.return_value = iter([_result(SHA_A), _result(SHA_B)])
        api.historical_result.return_value = _result(
            SHA_A, [{"offset": 1, "identifier": "$a", "data": "evil"}]
        )
        hunter = _hunter(api)
        with patch.object(hunter, "_create_hunt", return_value=_hunt("111")) as create:
            outcome = hunter.run(RULE)
        create.assert_called_once_with(RULE)
        assert outcome.hunt_id == "111"
        assert outcome.status == "COMPLETED"
        assert outcome.total_matches == 2
        assert [r.sha256 for r in outcome.results] == [SHA_A, SHA_B]
        assert outcome.strings[SHA_A] == ["$a at offset 1: evil"]
        assert not outcome.timed_out and not outcome.failed

    def test_create_call_sends_rule_name_window_and_community(self):
        api = _api()
        fake_create = MagicMock()
        fake_create.return_value.result.return_value = _hunt("9")
        with patch("polyswarm_api.resources.HistoricalHunt.create", fake_create):
            _hunter(api)._create_hunt(RULE)
        args, kwargs = fake_create.call_args
        assert args == (api,)
        assert kwargs["yara"] == RULE
        assert kwargs["window_days"] == 30
        assert kwargs["community"] == "default"
        assert kwargs["ruleset_name"].startswith("OpenCTI demo_rule ")

    def test_results_are_capped_and_deduplicated(self):
        api = _api()
        api.historical_get.return_value = _hunt(status="COMPLETED", count=500)
        api.historical_results.return_value = iter(
            [_result(SHA_A), _result(SHA_A), _result(SHA_B), _result(SHA_C)]
        )
        api.historical_result.return_value = _result(SHA_A, None)
        hunter = _hunter(api, max_results=2)
        with patch.object(hunter, "_create_hunt", return_value=_hunt("1")):
            outcome = hunter.run(RULE)
        assert [r.sha256 for r in outcome.results] == [SHA_A, SHA_B]
        assert outcome.total_matches == 500

    def test_timeout_reports_running_and_keeps_hunt(self):
        api = _api()
        api.historical_get.return_value = _hunt(status="PENDING")
        hunter = _hunter(api, timeout=60)
        with patch.object(hunter, "_create_hunt", return_value=_hunt("7")):
            outcome = hunter.run(RULE)
        assert outcome.timed_out and outcome.hunt_id == "7"
        assert outcome.results == []
        api.historical_results.assert_not_called()
        # polling is bounded by the timeout, never forever
        assert (
            api.historical_get.call_count <= 60 // yara_hunt.POLL_INTERVAL_SECONDS + 1
        )

    def test_limited_status_is_a_finished_hunt(self):
        api = _api()
        api.historical_get.return_value = _hunt(status="LIMITED", count=10049)
        api.historical_results.return_value = iter([_result(SHA_A)])
        api.historical_result.return_value = _result(SHA_A, None)
        hunter = _hunter(api)
        created = _hunt("2", "LIMITED", 10049)
        with patch.object(hunter, "_create_hunt", return_value=created):
            outcome = hunter.run(RULE)
        assert outcome.status == "LIMITED" and not outcome.failed
        assert outcome.total_matches == 10049

    def test_failed_status_is_reported(self):
        hunter = _hunter(_api())
        with patch.object(hunter, "_create_hunt", return_value=_hunt("3", "FAILED")):
            outcome = hunter.run(RULE)
        assert outcome.failed and "FAILED" in outcome.error

    def test_invalid_rule_rejected_by_polyswarm(self):
        hunter = _hunter(_api())
        err = polyswarm_exceptions.InvalidYaraRulesException(
            "line 3: unknown identifier"
        )
        with patch.object(hunter, "_create_hunt", side_effect=err):
            outcome = hunter.run(RULE)
        assert outcome.failed and "unknown identifier" in outcome.error
        assert outcome.hunt_id is None

    def test_other_start_error_is_reported_not_raised(self):
        hunter = _hunter(_api())
        with patch.object(hunter, "_create_hunt", side_effect=RuntimeError("quota")):
            outcome = hunter.run(RULE)
        assert outcome.failed and "quota" in outcome.error

    def test_local_validation_failure_never_calls_polyswarm(self):
        hunter = _hunter(_api())
        with patch.object(yara_hunt, "validate_rule", return_value="bad rule"):
            with patch.object(hunter, "_create_hunt") as create:
                outcome = hunter.run(RULE)
        create.assert_not_called()
        assert outcome.failed and "bad rule" in outcome.error

    def test_no_results_exception_is_an_empty_hunt(self):
        api = _api()
        api.historical_get.return_value = _hunt(status="COMPLETED", count=0)
        api.historical_results.side_effect = polyswarm_exceptions.NoResultsException(
            "none"
        )
        hunter = _hunter(api)
        created = _hunt("4", "COMPLETED", 0)
        with patch.object(hunter, "_create_hunt", return_value=created):
            outcome = hunter.run(RULE)
        assert outcome.results == [] and not outcome.failed and outcome.error is None


class TestNoSecondHunt:
    def test_running_hunt_in_state_is_followed(self):
        helper = FakeHelper()
        helper.state = {yara_hunt.STATE_KEY: {rule_digest(RULE): {"hunt_id": "55"}}}
        api = _api()
        # first call is the state lookup (still running), then the wait loop
        api.historical_get.side_effect = [
            _hunt("55", "PENDING"),
            _hunt("55", "COMPLETED", 1),
        ]
        api.historical_results.return_value = iter([_result(SHA_A)])
        api.historical_result.return_value = _result(SHA_A, None)
        hunter = _hunter(api, helper=helper)
        with patch.object(hunter, "_create_hunt") as create:
            outcome = hunter.run(RULE)
        create.assert_not_called()
        assert outcome.reused and outcome.hunt_id == "55"

    @pytest.mark.parametrize("status", ["COMPLETED", "LIMITED"])
    def test_finished_hunt_in_state_is_reused_not_restarted(self, status):
        helper = FakeHelper()
        helper.state = {yara_hunt.STATE_KEY: {rule_digest(RULE): {"hunt_id": "55"}}}
        api = _api()
        api.historical_get.return_value = _hunt("55", status, 1)
        api.historical_results.return_value = iter([_result(SHA_A)])
        api.historical_result.return_value = _result(SHA_A, None)
        hunter = _hunter(api, helper=helper)
        with patch.object(hunter, "_create_hunt") as create:
            outcome = hunter.run(RULE)
        create.assert_not_called()
        assert outcome.reused and outcome.hunt_id == "55"
        assert [r.sha256 for r in outcome.results] == [SHA_A]

    def test_timeout_then_reenrich_reads_results_without_second_hunt(self):
        helper = FakeHelper()
        api = _api()
        api.historical_get.return_value = _hunt("8", "PENDING")
        first = _hunter(api, timeout=60, helper=helper)
        with patch.object(first, "_create_hunt", return_value=_hunt("8")) as create:
            assert first.run(RULE).timed_out
        create.assert_called_once()
        # later the hunt has finished
        api.historical_get.return_value = _hunt("8", "COMPLETED", 1)
        api.historical_results.return_value = iter([_result(SHA_A)])
        api.historical_result.return_value = _result(SHA_A, None)
        second = _hunter(api, helper=helper)
        with patch.object(second, "_create_hunt") as create2:
            outcome = second.run(RULE)
        create2.assert_not_called()
        assert outcome.hunt_id == "8" and len(outcome.results) == 1

    def test_finished_hunt_older_than_its_window_starts_a_new_one(self):
        helper = FakeHelper()
        helper.state = {yara_hunt.STATE_KEY: {rule_digest(RULE): {"hunt_id": "55"}}}
        api = _api()
        old = datetime.now(timezone.utc) - timedelta(days=31)
        api.historical_get.return_value = _hunt("55", "COMPLETED", 1, created=old)
        api.historical_list.return_value = iter([])
        api.historical_results.return_value = iter([])
        hunter = _hunter(api, helper=helper)
        created = _hunt("57", "COMPLETED", 0)
        with patch.object(hunter, "_create_hunt", return_value=created) as create:
            outcome = hunter.run(RULE)
        create.assert_called_once()
        assert outcome.hunt_id == "57" and not outcome.reused
        note = build_note(INDICATOR, RULE, outcome, "identity--x")
        assert "older than its 30 day window" in note["content"]
        assert "55" in note["content"]

    def test_stale_state_hunt_then_reusable_account_hunt_has_consistent_note(self):
        helper = FakeHelper()
        helper.state = {yara_hunt.STATE_KEY: {rule_digest(RULE): {"hunt_id": "55"}}}
        api = _api()
        old = datetime.now(timezone.utc) - timedelta(days=40)
        name = YaraHunter.hunt_name(RULE)
        api.historical_get.side_effect = [
            _hunt("55", "COMPLETED", 1, created=old),
            _hunt("71", "COMPLETED", 0),
        ]
        api.historical_list.return_value = iter([_hunt("71", "PENDING", name=name)])
        api.historical_results.return_value = iter([])
        hunter = _hunter(api, helper=helper)
        with patch.object(hunter, "_create_hunt") as create:
            outcome = hunter.run(RULE)
        create.assert_not_called()
        assert outcome.reused and outcome.hunt_id == "71"
        assert outcome.replaced_hunt_id is None
        content = build_note(INDICATOR, RULE, outcome, "identity--x")["content"]
        assert "reused" in content and "new hunt was started" not in content.replace(
            "no new hunt was started", ""
        )

    def test_finished_hunt_within_its_window_is_reused(self):
        helper = FakeHelper()
        helper.state = {yara_hunt.STATE_KEY: {rule_digest(RULE): {"hunt_id": "55"}}}
        api = _api()
        recent = datetime.now(timezone.utc) - timedelta(days=29)
        api.historical_get.return_value = _hunt("55", "COMPLETED", 0, created=recent)
        api.historical_results.return_value = iter([])
        hunter = _hunter(api, helper=helper)
        with patch.object(hunter, "_create_hunt") as create:
            outcome = hunter.run(RULE)
        create.assert_not_called()
        assert outcome.reused

    def test_failed_hunt_in_state_is_not_reused(self):
        helper = FakeHelper()
        helper.state = {yara_hunt.STATE_KEY: {rule_digest(RULE): {"hunt_id": "55"}}}
        api = _api()
        api.historical_get.return_value = _hunt("55", "FAILED")
        api.historical_results.return_value = iter([])
        hunter = _hunter(api, helper=helper)
        created = _hunt("56", "COMPLETED", 0)
        with patch.object(hunter, "_create_hunt", return_value=created) as create:
            outcome = hunter.run(RULE)
        create.assert_called_once()
        assert outcome.hunt_id == "56" and not outcome.reused

    def test_empty_account_list_starts_a_hunt(self):
        api = _api()
        api.historical_list.side_effect = polyswarm_exceptions.NoResultsException("x")
        api.historical_get.return_value = _hunt("9", "COMPLETED", 0)
        api.historical_results.return_value = iter([])
        hunter = _hunter(api)
        with patch.object(hunter, "_create_hunt", return_value=_hunt("9")) as create:
            hunter.run(RULE)
        create.assert_called_once()
        api.historical_list.assert_called_once_with(
            since=yara_hunt.ACCOUNT_LOOKBACK_SECONDS
        )

    def test_running_hunt_on_the_account_is_followed(self):
        api = _api()
        name = YaraHunter.hunt_name(RULE)
        api.historical_list.return_value = iter(
            [_hunt("70", "FAILED", name=name), _hunt("71", "PENDING", name=name)]
        )
        api.historical_get.return_value = _hunt("71", "COMPLETED", 0)
        api.historical_results.return_value = iter([])
        hunter = _hunter(api)
        with patch.object(hunter, "_create_hunt") as create:
            outcome = hunter.run(RULE)
        create.assert_not_called()
        assert outcome.reused and outcome.hunt_id == "71"

    def test_new_hunt_is_remembered_in_state(self):
        helper = FakeHelper()
        api = _api()
        api.historical_get.return_value = _hunt("9", "COMPLETED", 0)
        api.historical_results.return_value = iter([])
        hunter = _hunter(api, helper=helper)
        with patch.object(hunter, "_create_hunt", return_value=_hunt("9")):
            hunter.run(RULE)
        assert helper.state[yara_hunt.STATE_KEY][rule_digest(RULE)]["hunt_id"] == "9"


# ===========================================================================
# STIX output
# ===========================================================================
def _outcome(**kw):
    outcome = HuntOutcome()
    outcome.hunt_id = "111"
    outcome.status = "COMPLETED"
    outcome.window_days = 30
    outcome.total_matches = 2
    outcome.results = [_result(SHA_A), _result(SHA_B)]
    outcome.strings = {SHA_A: ["$a at offset 1: evil"]}
    for key, value in kw.items():
        setattr(outcome, key, value)
    return outcome


INDICATOR = {"id": IND_ID, "type": "indicator", "pattern_type": "yara", "pattern": RULE}


class TestStix:
    def test_note_content_for_finished_hunt(self):
        note = build_note(INDICATOR, RULE, _outcome(), "identity--x")
        text = note["content"]
        assert "Hunt id: 111" in text
        assert "Rule: demo_rule" in text
        assert "Window: 30 days" in text
        assert "Matches reported by PolySwarm: 2" in text
        assert "Files imported: 2" in text
        assert "$a at offset 1: evil" in text
        assert note["object_refs"] == [IND_ID]
        assert note["content"].isascii() and note["abstract"].isascii()

    def test_note_for_running_hunt_names_the_hunt(self):
        outcome = _outcome(timed_out=True, status="PENDING")
        note = build_note(INDICATOR, RULE, outcome, "identity--x")
        assert "still running" in note["abstract"]
        assert "Hunt id: 111" in note["content"]

    def test_note_for_failure_has_the_error(self):
        out = HuntOutcome()
        out.failed = True
        out.error = "PolySwarm rejected the YARA rule: bad"
        note = build_note(INDICATOR, RULE, out, "identity--x")
        assert "rejected" in note["content"] and "failed" in note["abstract"]

    def test_note_id_is_stable_per_indicator_and_hunt(self):
        a = build_note(INDICATOR, RULE, _outcome(), "identity--x")
        b = build_note(INDICATOR, RULE, _outcome(timed_out=True), "identity--x")
        assert a["id"] == b["id"]

    def test_file_id_covers_all_hashes(self):
        import stix2

        converter = ConverterToStix(StubHelper())
        objects = build_file_objects(converter, INDICATOR, _outcome())
        file_obj = next(o for o in objects if o["type"] == "file")
        expected = stix2.File(
            hashes={"SHA-256": SHA_A, "MD5": "d" * 32, "SHA-1": "e" * 40}
        )
        assert file_obj["id"] == expected.id

    def test_files_carry_the_pivot_result_label(self):
        from polyswarm_enrichment.pivots import has_pivot_label

        converter = ConverterToStix(StubHelper())
        objects = build_file_objects(converter, INDICATOR, _outcome())
        files = [o for o in objects if o["type"] == "file"]
        assert files
        for f in files:
            assert f["x_opencti_labels"] == ["polyswarm-pivot-result"]
            assert has_pivot_label(f)

    def test_invalid_extra_hashes_are_dropped(self):
        converter = ConverterToStix(StubHelper())
        result = _result(SHA_A)
        result.md5 = "not-a-hash"
        outcome = _outcome(results=[result])
        file_obj = build_file_objects(converter, INDICATOR, outcome)[0]
        assert "MD5" not in file_obj["hashes"]

    def test_files_have_hashes_and_related_to(self):
        converter = ConverterToStix(StubHelper())
        objects = build_file_objects(converter, INDICATOR, _outcome())
        files = [o for o in objects if o["type"] == "file"]
        rels = [o for o in objects if o["type"] == "relationship"]
        assert len(files) == 2 and len(rels) == 2
        assert files[0]["hashes"] == {
            "SHA-256": SHA_A,
            "MD5": "d" * 32,
            "SHA-1": "e" * 40,
        }
        assert all(r.relationship_type == "related-to" for r in rels)
        assert all(r.source_ref == IND_ID for r in rels)


# ===========================================================================
# Connector routing
# ===========================================================================
def _connector(enabled=True, scope="stixfile,indicator"):
    connector = object.__new__(ConnectorTemplate)
    connector.helper = FakeHelper()
    connector.helper.connect_scope = scope
    connector.stix_objects_list = []
    connector.converter_to_stix = ConverterToStix(connector.helper)
    connector.client = MagicMock()
    connector.max_tlp = "TLP:RED"
    connector.yara_hunt_enabled = enabled
    connector.yara_hunt_window_days = 30
    connector.yara_hunt_timeout = 1800
    connector.yara_hunt_max_results = 50
    connector._send_bundle = MagicMock(return_value="[CONNECTOR] sent")
    return connector


def _message(pattern_type="yara", pattern=RULE, event_type="enrichment"):
    indicator = dict(INDICATOR, pattern_type=pattern_type, pattern=pattern)
    return {
        "enrichment_entity": {"entity_type": "Indicator", "id": "internal-id"},
        "stix_objects": [indicator],
        "stix_entity": indicator,
        "event_type": event_type,
    }


class TestConnector:
    def test_disabled_ignores_indicator_without_touching_polyswarm(self):
        connector = _connector(enabled=False)
        with patch("polyswarm_enrichment.connector.YaraHunter") as hunter:
            result = connector.process_message(_message())
        hunter.assert_not_called()
        assert "Ignored" in result
        connector._send_bundle.assert_not_called()

    def test_disabled_playbook_gets_original_bundle(self):
        connector = _connector(enabled=False)
        message = _message(event_type=None)
        connector.process_message(message)
        connector._send_bundle.assert_called_once_with(message["stix_objects"])

    def test_explicit_env_scope_without_indicator_still_hunts(self):
        # The helper's scope comes from CONNECTOR_SCOPE in the environment and
        # may lack Indicator; the setting alone decides
        connector = _connector(
            scope="StixFile,Artifact,Url,Domain-Name,IPv4-Addr,IPv6-Addr"
        )
        with patch("polyswarm_enrichment.connector.YaraHunter") as hunter:
            hunter.return_value.run.return_value = MagicMock(
                results=[], failed=False, timed_out=False, status="FINISHED"
            )
            hunter.return_value.window_days = 30
            with patch("polyswarm_enrichment.connector.build_note", return_value={}):
                connector.process_message(_message())
        hunter.return_value.run.assert_called_once()

    def test_non_yara_indicator_is_ignored_quietly(self):
        connector = _connector()
        with patch("polyswarm_enrichment.connector.YaraHunter") as hunter:
            result = connector.process_message(
                _message(pattern_type="stix", pattern="[file:name = 'a']")
            )
        hunter.assert_not_called()
        assert "not a YARA rule" in result

    def test_tlp_above_max_blocks_hunt(self):
        connector = _connector()
        connector.max_tlp = "TLP:GREEN"
        message = _message()
        message["enrichment_entity"]["objectMarking"] = [{"definition": "TLP:RED"}]
        with patch("polyswarm_enrichment.connector.YaraHunter") as hunter:
            assert "max_tlp" in connector.process_message(message)
        hunter.assert_not_called()

    def test_unresolved_marking_fails_closed(self):
        connector = _connector()
        connector.max_tlp = "TLP:AMBER"
        message = _message()
        message["stix_entity"]["object_marking_refs"] = [
            "marking-definition--00000000-0000-4000-8000-000000000000"
        ]
        with patch("polyswarm_enrichment.connector.YaraHunter") as hunter:
            assert "Ignored" in connector.process_message(message)
        hunter.assert_not_called()

    def test_enabled_hunts_and_sends_note_and_files(self):
        connector = _connector()
        with patch("polyswarm_enrichment.connector.YaraHunter") as hunter_cls:
            hunter_cls.return_value.run.return_value = _outcome()
            hunter_cls.return_value.window_days = 30
            connector.process_message(_message())
        hunter_cls.return_value.run.assert_called_once_with(RULE)
        sent = connector._send_bundle.call_args[0][0]
        types = [o["type"] for o in sent]
        assert types.count("note") == 1
        assert types.count("file") == 2
        assert types.count("relationship") == 2
        assert any(o.get("id") == IND_ID for o in sent)

    def test_timed_out_hunt_sends_note_only(self):
        connector = _connector()
        outcome = _outcome(timed_out=True, status="PENDING", results=[])
        with patch("polyswarm_enrichment.connector.YaraHunter") as hunter_cls:
            hunter_cls.return_value.run.return_value = outcome
            hunter_cls.return_value.window_days = 30
            connector.process_message(_message())
        sent = connector._send_bundle.call_args[0][0]
        assert [o["type"] for o in sent if o["type"] in ("file", "relationship")] == []
        note = next(o for o in sent if o["type"] == "note")
        assert "111" in note["content"]

    def test_derived_objects_keep_markings(self):
        connector = _connector()
        message = _message()
        message["stix_entity"]["object_marking_refs"] = [TLP_CLEAR]
        with patch("polyswarm_enrichment.connector.YaraHunter") as hunter_cls:
            hunter_cls.return_value.run.return_value = _outcome()
            hunter_cls.return_value.window_days = 30
            connector.process_message(message)
        sent = connector._send_bundle.call_args[0][0]
        derived = [o for o in sent if o["type"] in ("note", "file", "relationship")]
        assert derived
        for obj in derived:
            assert obj["object_marking_refs"] == [TLP_CLEAR]

    def test_derived_objects_carry_union_of_stix_and_opencti_markings(self):
        connector = _connector()
        message = _message()
        message["stix_entity"]["object_marking_refs"] = [TLP_CLEAR]
        message["enrichment_entity"]["objectMarking"] = [
            {"definition": "TLP:GREEN", "standard_id": TLP_GREEN},
            {"definition": "TLP:CLEAR", "standard_id": TLP_CLEAR},
        ]
        with patch("polyswarm_enrichment.connector.YaraHunter") as hunter_cls:
            hunter_cls.return_value.run.return_value = _outcome()
            hunter_cls.return_value.window_days = 30
            connector.process_message(message)
        sent = connector._send_bundle.call_args[0][0]
        derived = [o for o in sent if o["type"] in ("note", "file", "relationship")]
        assert derived
        for obj in derived:
            assert obj["object_marking_refs"] == [TLP_CLEAR, TLP_GREEN]


# ===========================================================================
# Settings
# ===========================================================================
class TestSettings:
    @staticmethod
    def _settings(**polyswarm):
        from test_settings import _settings_from

        return _settings_from(polyswarm)

    def test_defaults_off(self):
        s = self._settings()
        assert s.polyswarm.yara_hunt_enabled is False
        assert s.polyswarm.yara_hunt_window_days == 30
        assert s.polyswarm.yara_hunt_timeout == 300
        assert s.polyswarm.yara_hunt_max_results == 50
        assert "Indicator" not in s.connector.scope

    def test_enabled_adds_indicator_scope_once(self):
        s = self._settings(yara_hunt_enabled=True)
        assert list(s.connector.scope).count("Indicator") == 1
        assert "StixFile" in s.connector.scope

    @pytest.mark.parametrize("days", [0, 7, 45, 365])
    def test_bad_window_rejected(self, days):
        with pytest.raises(Exception):
            self._settings(yara_hunt_window_days=days)

    @pytest.mark.parametrize("days", [30, 60, 90, 180])
    def test_valid_window_accepted(self, days):
        settings = self._settings(yara_hunt_window_days=days)
        assert settings.polyswarm.yara_hunt_window_days == days
