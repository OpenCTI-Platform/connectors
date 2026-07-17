"""Unit tests for email_client.factory.

Only the unsupported-protocol path is exercised directly to avoid pulling in
optional protocol libraries (msal, exchangelib, google-auth) that may not be
present in the unit test environment. Routing for the supported protocols is
verified by mocking the imports.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from email_client.factory import create_email_client


def _cfg(**email_cases_overrides):
    """Build a fake config object exposing .email_cases like ConnectorSettings does."""
    defaults = {
        "protocol": "imap",
        "imap_host": "h",
        "imap_port": 993,
        "imap_username": "u",
        "imap_password": "p",
        "imap_folder": "INBOX",
        "imap_use_ssl": True,
        "graph_tenant_id": "",
        "graph_client_id": "",
        "graph_client_secret": "",
        "graph_user_id": "",
        "gmail_credentials_file": "",
        "gmail_user_id": "me",
        "ews_server": "",
        "ews_username": "",
        "ews_password": "",
        "ews_auth_type": "NTLM",
        "tls_verify": True,
    }
    defaults.update(email_cases_overrides)
    return SimpleNamespace(email_cases=SimpleNamespace(**defaults))


class TestUnsupportedProtocol:
    def test_unsupported_raises(self):
        # Bypass Pydantic validation by passing a plain SimpleNamespace
        cfg = _cfg(protocol="pop3")
        with pytest.raises(ValueError, match="Unsupported email protocol"):
            create_email_client(cfg)


class TestProtocolRouting:
    """Routing tests need the optional protocol libraries installed because the
    factory triggers a real `from email_client.<protocol>_client import ...`
    inside the function body. Each test uses `pytest.importorskip` to skip
    cleanly when the corresponding library isn't available."""

    def test_imap_routing(self):
        # imaplib is stdlib, always available
        import email_client.imap_client  # noqa: F401  pylint: disable=import-outside-toplevel,unused-import

        cfg = _cfg(protocol="imap")
        with patch("email_client.imap_client.ImapClient") as mock_cls:
            mock_cls.return_value = "imap-instance"
            assert create_email_client(cfg) == "imap-instance"
            kwargs = mock_cls.call_args.kwargs
            assert kwargs["host"] == "h"
            assert kwargs["port"] == 993
            assert kwargs["username"] == "u"
            assert kwargs["use_ssl"] is True

    def test_microsoft_graph_routing(self):
        pytest.importorskip("msal")
        import email_client.graph_client  # noqa: F401  pylint: disable=import-outside-toplevel,unused-import

        cfg = _cfg(
            protocol="microsoft_graph",
            graph_tenant_id="t",
            graph_client_id="c",
            graph_client_secret="s",
            graph_user_id="user@example.com",
        )
        with patch("email_client.graph_client.GraphClient") as mock_cls:
            mock_cls.return_value = "graph-instance"
            assert create_email_client(cfg) == "graph-instance"
            kwargs = mock_cls.call_args.kwargs
            assert kwargs["tenant_id"] == "t"
            assert kwargs["client_id"] == "c"
            assert kwargs["client_secret"] == "s"
            assert kwargs["user_id"] == "user@example.com"

    def test_gmail_routing(self):
        pytest.importorskip("google.auth")
        import email_client.gmail_client  # noqa: F401  pylint: disable=import-outside-toplevel,unused-import

        cfg = _cfg(
            protocol="gmail",
            gmail_credentials_file="/run/secrets/gmail.json",
            gmail_user_id="me",
        )
        with patch("email_client.gmail_client.GmailClient") as mock_cls:
            mock_cls.return_value = "gmail-instance"
            assert create_email_client(cfg) == "gmail-instance"
            kwargs = mock_cls.call_args.kwargs
            assert kwargs["credentials_file"] == "/run/secrets/gmail.json"
            assert kwargs["user_id"] == "me"

    def test_ews_routing(self):
        pytest.importorskip("exchangelib")
        import email_client.ews_client  # noqa: F401  pylint: disable=import-outside-toplevel,unused-import

        cfg = _cfg(
            protocol="ews",
            ews_server="https://exchange.local/EWS/Exchange.asmx",
            ews_username="DOMAIN\\u",
            ews_password="p",
            ews_auth_type="NTLM",
        )
        with patch("email_client.ews_client.EwsClient") as mock_cls:
            mock_cls.return_value = "ews-instance"
            assert create_email_client(cfg) == "ews-instance"
            kwargs = mock_cls.call_args.kwargs
            assert kwargs["server"] == "https://exchange.local/EWS/Exchange.asmx"
            assert kwargs["auth_type"] == "NTLM"
