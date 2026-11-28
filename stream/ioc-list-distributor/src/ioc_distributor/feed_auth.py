"""Optional authentication of the feed downloads (FEED_DISTRIBUTOR_AUTH_*).

Modes:
  none    no check (default)
  basic   "Authorization: Basic base64(user:passtoken)"  - user + passtoken
  bearer  "Authorization: Bearer <passtoken>"            - passtoken only

FeedAuthMiddleware is a plain ASGI middleware: every path is protected except the public ones
(/health by default), so an unknown path answers 401, not 404, and reveals nothing.
Credentials are compared in constant time and never logged.

Generate a passtoken:  python -m ioc_distributor.feed_auth make-token
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
import secrets
import sys
import time
from typing import TYPE_CHECKING

from common.config import AUTH_MODES

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

log = logging.getLogger("feed-distributor")

REALM = "IOC feeds"


class FeedAuth:
    """Checks an Authorization header against the configured mode and credentials."""

    def __init__(
        self, mode: str = "none", user: str | None = None, passtoken: str | None = None
    ) -> None:
        if mode not in AUTH_MODES:
            raise ValueError(f"unknown auth mode {mode!r}")
        self.mode = mode
        self._user = (user or "").encode("utf-8")
        self._passtoken = (passtoken or "").encode("utf-8")

    @property
    def enabled(self) -> bool:
        """Whether the feeds need credentials."""
        return self.mode != "none"

    def challenge(self, header_present: bool = False) -> str:
        """Value of the WWW-Authenticate header sent with a 401."""
        if self.mode == "bearer":
            return f'Bearer realm="{REALM}"' + (
                ', error="invalid_token"' if header_present else ""
            )
        return f'Basic realm="{REALM}", charset="UTF-8"'

    def check(self, authorization: str | None) -> tuple[bool, str]:
        """Return (allowed, reason). The reason never contains the credentials."""
        if not self.enabled:
            return True, "auth disabled"
        if not authorization or not authorization.strip():
            return False, "no Authorization header"
        scheme, _, value = authorization.strip().partition(" ")
        value = value.strip()
        expected = "basic" if self.mode == "basic" else "bearer"
        if scheme.lower() != expected:
            return (
                False,
                f"wrong scheme ({scheme[:20]!r}, expected {expected.capitalize()})",
            )
        if not value:
            return False, "empty credentials"
        if self.mode == "bearer":
            ok = hmac.compare_digest(value.encode("utf-8"), self._passtoken)
            return (True, "ok") if ok else (False, "wrong token")
        return self._check_basic(value)

    def _check_basic(self, value: str) -> tuple[bool, str]:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return False, "malformed Basic credentials (not base64)"
        user, sep, passtoken = decoded.partition(b":")
        if not sep:
            return False, "malformed Basic credentials (no ':')"
        # Compare both, always, so the timing does not tell which one is wrong.
        user_ok = hmac.compare_digest(user, self._user)
        pass_ok = hmac.compare_digest(passtoken, self._passtoken)
        if user_ok and pass_ok:
            return True, "ok"
        return False, "wrong user or passtoken"


class FeedAuthMiddleware:
    """ASGI middleware enforcing FeedAuth on every path except public_paths."""

    LOG_INTERVAL_SECONDS = 60  # at most one failure line per client IP per interval

    def __init__(
        self, app: ASGIApp, auth: FeedAuth, public_paths: tuple = ("/health",)
    ) -> None:
        self.app = app
        self.auth = auth
        self.public_paths = frozenset(public_paths)
        self._last_log: dict[str, float] = {}
        self._suppressed: dict[str, int] = {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or not self.auth.enabled
            or scope.get("path") in self.public_paths
        ):
            await self.app(scope, receive, send)
            return
        authorization = None
        for key, val in scope.get("headers") or []:
            if key.lower() == b"authorization":
                authorization = val.decode("latin-1")
                break
        allowed, reason = self.auth.check(authorization)
        if allowed:
            await self.app(scope, receive, send)
            return
        self._log_failure(scope, reason)
        body = json.dumps({"detail": "authentication required"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (
                        b"www-authenticate",
                        self.auth.challenge(authorization is not None).encode(),
                    ),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body if scope.get("method") != "HEAD" else b"",
            }
        )

    def _log_failure(self, scope: Scope, reason: str) -> None:
        client = (scope.get("client") or ("unknown", 0))[0]
        now = time.monotonic()
        last = self._last_log.get(client)
        if last is not None and now - last < self.LOG_INTERVAL_SECONDS:
            self._suppressed[client] = self._suppressed.get(client, 0) + 1
            return
        suppressed = self._suppressed.pop(client, 0)
        self._last_log[client] = now
        if len(self._last_log) > 10000:  # bound the memory if many sources fail
            self._last_log.clear()
            self._suppressed.clear()
        extra = (
            f" (+{suppressed} more failure(s) from this client in the last minute)"
            if suppressed
            else ""
        )
        log.warning(
            "auth failed: %s %s %s from %s: %s%s",
            self.auth.mode,
            scope.get("method"),
            scope.get("path"),
            client,
            reason,
            extra,
        )


def make_token(nbytes: int = 32) -> str:
    """A random passtoken that is safe for Basic, Bearer and docker-compose.yml (letters, digits, - and _)."""
    return secrets.token_urlsafe(nbytes)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "make-token":
        print(make_token())
    else:
        print("usage: python -m ioc_distributor.feed_auth make-token")
        sys.exit(2)
