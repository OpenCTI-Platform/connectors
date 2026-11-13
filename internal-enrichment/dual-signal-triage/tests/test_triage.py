import importlib.util
import sys
from pathlib import Path

_TRIAGE = Path(__file__).resolve().parents[1] / "src" / "connector" / "triage.py"
_spec = importlib.util.spec_from_file_location("dual_signal_triage_logic", _TRIAGE)
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load triage module from {_TRIAGE}")
triage = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = triage
_spec.loader.exec_module(triage)


def test_ml_only_gid_411():
    result = triage.triage_text("SnortML alert GeneratorID=411 high impact")
    assert result.signal_basis == "ml_only"
    assert result.disposition == "escalate"
    assert result.deny_auto_contain is True
    assert "remediation:deny-auto-contain" in result.labels


def test_signature_high():
    result = triage.triage_text("Classification: A Network Trojan was Detected")
    assert result.signal_basis == "signature"
    assert result.disposition == "gated_fix_now"
    assert result.deny_auto_contain is False


def test_corroborated_ocsf_flags():
    result = triage.triage_entity(
        {
            "name": "C2 candidate",
            "description": "signature and eve high",
            "labels": ["is_corroborated"],
        }
    )
    assert result.signal_basis == "corroborated"
    assert result.disposition == "gated_fix_now"
    assert "dual-signal:corroborated" in result.labels


def test_object_label_payload():
    result = triage.triage_entity(
        {
            "name": "incident",
            "objectLabel": [{"value": "is_ml_only"}, {"name": "snortml"}],
        }
    )
    assert result.signal_basis == "ml_only"
    assert result.deny_auto_contain is True


def test_ml_plus_signature_is_corroborated():
    result = triage.triage_text("gid 411 and A Network Trojan was Detected")
    assert result.signal_basis == "corroborated"


def test_unknown_defaults_to_accept():
    result = triage.triage_text("routine host inventory note")
    assert result.signal_basis == "unknown"
    assert result.disposition == "accept"
    assert result.deny_auto_contain is True
    assert "remediation:deny-auto-contain" in result.labels
