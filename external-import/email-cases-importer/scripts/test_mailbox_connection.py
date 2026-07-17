#!/usr/bin/env python3
"""Standalone mailbox connectivity tester for the Email Cases connector.

Exercises the exact `email_client.*` code paths the connector uses, without
pulling in OpenCTI, pycti, or the connectors-sdk. Use this to validate mailbox
credentials and network reachability before deploying the connector.

Examples
--------
IMAP:
    python scripts/test_mailbox_connection.py imap \\
        --host imap.example.com --username u --password p \\
        --sender alerts@example.com

Microsoft Graph (Office 365):
    python scripts/test_mailbox_connection.py microsoft_graph \\
        --tenant-id T --client-id C --client-secret S \\
        --user-id u@company.com --sender alerts@example.com

Gmail:
    python scripts/test_mailbox_connection.py gmail \\
        --credentials-file /path/creds.json --sender alerts@example.com

EWS (on-premise Exchange):
    python scripts/test_mailbox_connection.py ews \\
        --server https://exchange.local/EWS/Exchange.asmx \\
        --username 'DOMAIN\\u' --password p --sender alerts@example.com

EWS with Autodiscover (omit --server; username must be the SMTP address):
    python scripts/test_mailbox_connection.py ews \\
        --username alice@contoso.com --password p --sender alerts@example.com

Env var fallback
----------------
Any CLI flag can be omitted if the corresponding `EMAIL_CASES_*` env var is
set (same names as the connector's docker-compose.yml). CLI flags win.

Exit codes
----------
0  connection succeeded and sender fetch returned without error
1  connection or fetch failed
2  CLI / config error (missing required argument)
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

# Make `src/` importable so we can reuse the connector's email_client code
# as-is. The script lives at <connector>/scripts/, and src sits at <connector>/src.
THIS_DIR = Path(__file__).resolve().parent
SRC_DIR = THIS_DIR.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env(name: str, default: str = "") -> str:
    """Read an env var, returning default when missing or empty."""
    val = os.environ.get(name, "")
    return val if val else default


def _resolve(cli_value, env_name: str, default=""):
    """CLI value takes precedence; otherwise fall back to env var."""
    if cli_value not in (None, ""):
        return cli_value
    return _env(env_name, default)


def _require(value, flag: str, env_name: str):
    if not value:
        print(
            f"ERROR: missing required value. Pass {flag} or set {env_name}.",
            file=sys.stderr,
        )
        sys.exit(2)
    return value


def _fmt_since(raw: str | None):
    if not raw:
        return None
    try:
        # Accept both "YYYY-MM-DD" and full ISO 8601
        if len(raw) == 10:
            return datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        print(f"ERROR: --since must be ISO-8601 or YYYY-MM-DD ({exc})", file=sys.stderr)
        sys.exit(2)


def _print_header(title: str):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def _print_sample(messages, limit: int = 3):
    if not messages:
        print("No emails matched the sender filter.")
        return
    print(f"Showing the first {min(limit, len(messages))} of {len(messages)}:")
    print()
    for idx, msg in enumerate(messages[:limit], start=1):
        print(f"  [{idx}] subject      : {msg.subject!r}")
        print(f"      sender       : {msg.sender}")
        print(f"      date         : {msg.date.isoformat() if msg.date else '-'}")
        print(f"      thread_id    : {msg.thread_id or '-'}")
        print(f"      attachments  : {len(msg.attachments)}")
        for att in msg.attachments[:3]:
            print(
                f"                     - {att.filename} "
                f"({att.content_type}, {att.size} bytes)"
            )
        if len(msg.attachments) > 3:
            print(f"                     ... +{len(msg.attachments) - 3} more")
        print()


# ---------------------------------------------------------------------------
# Per-protocol client builders
# ---------------------------------------------------------------------------


def build_imap_client(args):
    from email_client.imap_client import ImapClient

    host = _require(
        _resolve(args.host, "EMAIL_CASES_IMAP_HOST"),
        "--host",
        "EMAIL_CASES_IMAP_HOST",
    )
    username = _require(
        _resolve(args.username, "EMAIL_CASES_IMAP_USERNAME"),
        "--username",
        "EMAIL_CASES_IMAP_USERNAME",
    )
    password = _require(
        _resolve(args.password, "EMAIL_CASES_IMAP_PASSWORD"),
        "--password",
        "EMAIL_CASES_IMAP_PASSWORD",
    )
    port = int(_resolve(args.port, "EMAIL_CASES_IMAP_PORT", "993"))
    folder = _resolve(args.folder, "EMAIL_CASES_IMAP_FOLDER", "INBOX")
    use_ssl = _resolve(args.use_ssl, "EMAIL_CASES_IMAP_USE_SSL", "true")
    use_ssl_bool = str(use_ssl).strip().lower() in ("1", "true", "yes", "on")
    tls_verify = _resolve(args.tls_verify, "EMAIL_CASES_TLS_VERIFY", "true")
    tls_verify_bool = str(tls_verify).strip().lower() in ("1", "true", "yes", "on")

    print(
        f"IMAP   host={host}:{port} folder={folder} ssl={use_ssl_bool} tls_verify={tls_verify_bool}"
    )
    return ImapClient(
        host=host,
        port=port,
        username=username,
        password=password,
        folder=folder,
        use_ssl=use_ssl_bool,
        tls_verify=tls_verify_bool,
    )


def build_graph_client(args):
    try:
        from email_client.graph_client import GraphClient
    except ImportError as exc:
        print(
            f"ERROR: could not import the Microsoft Graph client "
            f"(email_client.graph_client), which uses only 'requests': {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    tenant_id = _require(
        _resolve(args.tenant_id, "EMAIL_CASES_GRAPH_TENANT_ID"),
        "--tenant-id",
        "EMAIL_CASES_GRAPH_TENANT_ID",
    )
    client_id = _require(
        _resolve(args.client_id, "EMAIL_CASES_GRAPH_CLIENT_ID"),
        "--client-id",
        "EMAIL_CASES_GRAPH_CLIENT_ID",
    )
    client_secret = _require(
        _resolve(args.client_secret, "EMAIL_CASES_GRAPH_CLIENT_SECRET"),
        "--client-secret",
        "EMAIL_CASES_GRAPH_CLIENT_SECRET",
    )
    user_id = _require(
        _resolve(args.user_id, "EMAIL_CASES_GRAPH_USER_ID"),
        "--user-id",
        "EMAIL_CASES_GRAPH_USER_ID",
    )
    tls_verify = _resolve(args.tls_verify, "EMAIL_CASES_TLS_VERIFY", "true")
    tls_verify_bool = str(tls_verify).strip().lower() in ("1", "true", "yes", "on")

    print(f"Graph  tenant={tenant_id[:8]}... user={user_id}")
    return GraphClient(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        user_id=user_id,
        tls_verify=tls_verify_bool,
    )


def build_gmail_client(args):
    try:
        from email_client.gmail_client import GmailClient
    except ImportError as exc:
        print(
            f"ERROR: Gmail client requires 'google-auth'. Install: "
            f"pip install google-auth  ({exc})",
            file=sys.stderr,
        )
        sys.exit(1)

    credentials_file = _require(
        _resolve(args.credentials_file, "EMAIL_CASES_GMAIL_CREDENTIALS_FILE"),
        "--credentials-file",
        "EMAIL_CASES_GMAIL_CREDENTIALS_FILE",
    )
    if not Path(credentials_file).is_file():
        print(
            f"ERROR: credentials file not found: {credentials_file}",
            file=sys.stderr,
        )
        sys.exit(2)
    user_id = _resolve(args.user_id, "EMAIL_CASES_GMAIL_USER_ID", "me")
    tls_verify = _resolve(args.tls_verify, "EMAIL_CASES_TLS_VERIFY", "true")
    tls_verify_bool = str(tls_verify).strip().lower() in ("1", "true", "yes", "on")

    print(f"Gmail  user={user_id} creds={credentials_file}")
    return GmailClient(
        credentials_file=credentials_file,
        user_id=user_id,
        tls_verify=tls_verify_bool,
    )


def build_ews_client(args):
    try:
        from email_client.ews_client import EwsClient
    except ImportError as exc:
        print(
            f"ERROR: EWS client requires 'exchangelib'. Install: "
            f"pip install exchangelib  ({exc})",
            file=sys.stderr,
        )
        sys.exit(1)

    # --server is OPTIONAL: when omitted, the connector's EwsClient falls back
    # to exchangelib's Autodiscover using the primary SMTP address. Username
    # must therefore be an SMTP address in autodiscover mode.
    server = _resolve(args.server, "EMAIL_CASES_EWS_SERVER")
    username = _require(
        _resolve(args.username, "EMAIL_CASES_EWS_USERNAME"),
        "--username",
        "EMAIL_CASES_EWS_USERNAME",
    )
    password = _require(
        _resolve(args.password, "EMAIL_CASES_EWS_PASSWORD"),
        "--password",
        "EMAIL_CASES_EWS_PASSWORD",
    )
    auth_type = _resolve(args.auth_type, "EMAIL_CASES_EWS_AUTH_TYPE", "NTLM")
    tls_verify = _resolve(args.tls_verify, "EMAIL_CASES_TLS_VERIFY", "true")
    tls_verify_bool = str(tls_verify).strip().lower() in ("1", "true", "yes", "on")

    if server:
        print(f"EWS    server={server} user={username} auth={auth_type}")
    else:
        if "@" not in username:
            print(
                "WARN: --server omitted and --username does not look like an "
                "SMTP address. Autodiscover needs the primary SMTP address as "
                "the username (e.g. user@contoso.com).",
                file=sys.stderr,
            )
        print(f"EWS    server=(Autodiscover) user={username} auth={auth_type}")
    return EwsClient(
        server=server,  # empty string triggers autodiscover in EwsClient
        username=username,
        password=password,
        auth_type=auth_type,
        tls_verify=tls_verify_bool,
    )


BUILDERS = {
    "imap": build_imap_client,
    "microsoft_graph": build_graph_client,
    "gmail": build_gmail_client,
    "ews": build_ews_client,
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_test(args) -> int:
    # Resolve and validate the cross-cutting args BEFORE we print anything or
    # build the client, so errors surface cleanly at the top.
    sender = _require(
        _resolve(args.sender, "EMAIL_CASES_SENDER_ADDRESS"),
        "--sender",
        "EMAIL_CASES_SENDER_ADDRESS",
    )
    since = _fmt_since(args.since)
    max_results = int(args.max_results)

    _print_header(f"Mailbox connectivity test -- protocol: {args.protocol}")

    try:
        client = BUILDERS[args.protocol](args)
    except SystemExit:
        raise
    except Exception:
        print("ERROR: failed to build client.")
        traceback.print_exc()
        return 1

    # Step 1: connect
    _print_header("Step 1/3 -- connect")
    try:
        client.connect()
    except Exception:
        print("FAIL: connect() raised.")
        traceback.print_exc()
        return 1
    print("OK: connected.")

    # Step 2: fetch (with disconnect in finally so we always clean up)
    try:
        _print_header("Step 2/3 -- fetch emails")
        print(f"  sender      = {sender}")
        print(f"  since       = {since.isoformat() if since else '(none)'}")
        print(f"  max_results = {max_results}")
        try:
            messages = client.fetch_emails(
                sender=sender, since=since, max_results=max_results
            )
        except Exception:
            print("FAIL: fetch_emails() raised.")
            traceback.print_exc()
            return 1
        print(f"OK: received {len(messages)} message(s).")

        # Step 3: show a small sample
        _print_header("Step 3/3 -- sample")
        _print_sample(messages, limit=min(3, max_results))

    finally:
        try:
            client.disconnect()
            print("Disconnected.")
        except Exception:
            # Swallow -- we already reported the real problem (if any) above.
            pass

    _print_header("RESULT: PASS")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="test_mailbox_connection",
        description=(
            "Test connectivity to a mailbox using the same email_client code "
            "paths the Email Cases connector uses. Runs outside OpenCTI."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "protocol",
        choices=sorted(BUILDERS.keys()),
        help="Which protocol to test.",
    )

    # Common (all protocols)
    p.add_argument(
        "--sender", default=None, help="Sender email to filter on (required)."
    )
    p.add_argument(
        "--since",
        default=None,
        help="Only fetch emails received after this date (ISO-8601 or YYYY-MM-DD).",
    )
    p.add_argument(
        "--max-results",
        type=int,
        default=5,
        help="Maximum emails to fetch (default: 5).",
    )
    p.add_argument(
        "--tls-verify",
        default=None,
        help="Verify TLS certs (true/false). Default true.",
    )

    # IMAP / EWS shared
    p.add_argument("--username", default=None, help="[imap, ews] Username.")
    p.add_argument("--password", default=None, help="[imap, ews] Password.")

    # IMAP
    p.add_argument("--host", default=None, help="[imap] IMAP server hostname.")
    p.add_argument("--port", default=None, help="[imap] IMAP port (default 993).")
    p.add_argument(
        "--folder", default=None, help="[imap] Folder to monitor (default INBOX)."
    )
    p.add_argument(
        "--use-ssl",
        default=None,
        help="[imap] Use SSL/TLS (true/false). Default true.",
    )

    # Microsoft Graph
    p.add_argument(
        "--tenant-id", default=None, help="[microsoft_graph] Azure AD tenant ID."
    )
    p.add_argument(
        "--client-id", default=None, help="[microsoft_graph] Azure AD client ID."
    )
    p.add_argument(
        "--client-secret",
        default=None,
        help="[microsoft_graph] Azure AD client secret.",
    )
    p.add_argument(
        "--user-id",
        default=None,
        help="[microsoft_graph, gmail] Mailbox user ID or UPN.",
    )

    # Gmail
    p.add_argument(
        "--credentials-file",
        default=None,
        help="[gmail] Path to Google service account credentials JSON.",
    )

    # EWS
    p.add_argument(
        "--server",
        default=None,
        help=(
            "[ews] Exchange server URL. Omit to use Autodiscover "
            "(in that case --username must be the SMTP address)."
        ),
    )
    p.add_argument(
        "--auth-type",
        default=None,
        choices=["NTLM", "OAuth2", None],
        help="[ews] NTLM or OAuth2 (default NTLM).",
    )

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run_test(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
