from types import SimpleNamespace

import main
from pycti.entities.opencti_user import User


def test_main_module_exports_connector():
    from connector import ConnectorSettings, RSTThreatFeed

    assert RSTThreatFeed is not None
    assert ConnectorSettings is not None


def test_patch_pycti_create_token_normalizes_response(monkeypatch):
    calls = []

    def original(self, *args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        return {
            "token_id": "tok-1",
            "plaintext_token": "secret",
            "expires_at": None,
        }

    monkeypatch.setattr(User, "create_token", original)

    main._patch_pycti_create_token_response()
    patched_once = User.create_token
    assert getattr(patched_once, "_rst_threat_feed_patched", False) is True

    result = User.create_token(
        SimpleNamespace(), id="user-1", token_name="connector-token"
    )

    assert result["id"] == "tok-1"
    assert result["name"] == "connector-token"
    assert result["token_id"] == "tok-1"
    assert result["plaintext_token"] == "secret"
    assert len(calls) == 1
    assert calls[0]["kwargs"]["token_name"] == "connector-token"

    main._patch_pycti_create_token_response()
    assert User.create_token is patched_once
