"""Checks for the optional feed authentication (src/feed_auth.py and its settings in config.py).

Run: python tests/test_feed_auth.py (or pytest). No network and no extra package needed:
the middleware is driven with hand-made ASGI requests.
"""

import asyncio
import base64
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from common import config  # noqa: E402
from ioc_distributor.feed_auth import (  # noqa: E402
    FeedAuth,
    FeedAuthMiddleware,
    make_token,
)

USER, TOKEN = "feeduser", "S3cr3t-Passtoken_0123456789"


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


# ---------------------------------------------------------------- FeedAuth.check
def test_none_allows_everything():
    auth = FeedAuth("none")
    assert not auth.enabled
    assert auth.check(None)[0] and auth.check("Basic garbage")[0]


def test_basic():
    auth = FeedAuth("basic", USER, TOKEN)
    assert auth.check(basic(USER, TOKEN)) == (True, "ok")
    assert auth.check("basic " + basic(USER, TOKEN)[6:])[
        0
    ]  # scheme is case-insensitive
    assert not auth.check(basic(USER, "wrong"))[0]
    assert not auth.check(basic("other", TOKEN))[0]
    assert not auth.check(basic(USER, TOKEN + "x"))[0]
    assert not auth.check(None)[0]
    assert not auth.check("Bearer " + TOKEN)[0]  # wrong scheme
    assert not auth.check("Basic !!!notbase64")[0]
    assert not auth.check("Basic " + base64.b64encode(b"nocolon").decode())[0]
    assert not auth.check("Basic ")[0]


def test_basic_passtoken_may_contain_colon():
    auth = FeedAuth("basic", USER, "a:b:c-0123456789xyz")
    assert auth.check(basic(USER, "a:b:c-0123456789xyz"))[0]


def test_bearer():
    auth = FeedAuth("bearer", None, TOKEN)
    assert auth.check("Bearer " + TOKEN) == (True, "ok")
    assert auth.check("bearer " + TOKEN)[0]
    assert not auth.check("Bearer wrong")[0]
    assert not auth.check(basic(USER, TOKEN))[0]  # Basic refused in bearer mode
    assert not auth.check(None)[0]


def test_reason_never_contains_secret():
    auth = FeedAuth("basic", USER, TOKEN)
    for header in (basic(USER, "guess"), "Bearer " + TOKEN, "Basic xx", None):
        assert TOKEN not in auth.check(header)[1]


def test_challenge_header():
    assert FeedAuth("basic", USER, TOKEN).challenge().startswith('Basic realm="')
    assert FeedAuth("bearer", None, TOKEN).challenge().startswith('Bearer realm="')
    assert 'error="invalid_token"' in FeedAuth("bearer", None, TOKEN).challenge(
        header_present=True
    )


def test_make_token():
    token = make_token()
    assert len(token) >= 40 and all(c.isalnum() or c in "-_" for c in token)
    assert make_token() != token


# ---------------------------------------------------------------- middleware
async def _inner_app(scope, receive, send):
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
    await send({"type": "http.response.body", "body": b"1.2.3.4\n"})


def call(mw, path, authorization=None, method="GET"):
    headers = [(b"host", b"test")]
    if authorization is not None:
        headers.append((b"authorization", authorization.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "client": ("192.0.2.10", 5555),
    }
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(mw(scope, receive, send))
    start = sent[0]
    return (
        start["status"],
        dict(start["headers"]),
        b"".join(m.get("body", b"") for m in sent[1:]),
    )


def test_middleware_basic():
    mw = FeedAuthMiddleware(_inner_app, FeedAuth("basic", USER, TOKEN))
    status, headers, body = call(mw, "/feeds/ip.txt")
    assert status == 401 and headers[b"www-authenticate"].startswith(b"Basic realm=")
    assert call(mw, "/feeds/ip.txt", basic(USER, TOKEN))[0] == 200
    assert call(mw, "/feeds/ip.txt", basic(USER, "bad"))[0] == 401
    for path in ("/stats", "/", "/docs", "/openapi.json", "/feeds/nothere.txt"):
        assert call(mw, path)[0] == 401, path  # all protected, unknown paths too
    assert call(mw, "/health")[0] == 200  # public
    status, _, body = call(mw, "/feeds/ip.txt", method="HEAD")
    assert status == 401 and body == b""


def test_middleware_bearer():
    mw = FeedAuthMiddleware(_inner_app, FeedAuth("bearer", None, TOKEN))
    status, headers, _ = call(mw, "/feeds/hash.txt")
    assert status == 401 and headers[b"www-authenticate"].startswith(b"Bearer realm=")
    assert call(mw, "/feeds/hash.txt", "Bearer " + TOKEN)[0] == 200
    assert call(mw, "/feeds/hash.txt", "Bearer nope")[0] == 401


def test_middleware_none():
    mw = FeedAuthMiddleware(_inner_app, FeedAuth("none"))
    assert call(mw, "/feeds/ip.txt")[0] == 200 and call(mw, "/stats")[0] == 200


# ---------------------------------------------------------------- settings
P = "FEED_DISTRIBUTOR_"


def settings(**env):
    keys = [k for k in os.environ if k.startswith(P)]
    saved = {k: os.environ.pop(k) for k in keys}
    try:
        os.environ.update({P + k: v for k, v in env.items()})
        return config.feed_distributor_settings()
    finally:
        for k in list(os.environ):
            if k.startswith(P):
                del os.environ[k]
        os.environ.update(saved)


def expect_exit(fragment, **env):
    try:
        settings(**env)
    except SystemExit as exc:
        assert fragment in str(exc), str(exc)
        return
    raise AssertionError(f"expected a startup error containing {fragment!r}")


def test_settings_default_none():
    s = settings()
    assert s.auth_mode == "none" and s.auth_passtoken is None and s.warnings == ()


def test_settings_valid_and_warnings():
    s = settings(AUTH_MODE="basic", AUTH_USER=USER, AUTH_PASSTOKEN=TOKEN)
    assert (s.auth_mode, s.auth_user, s.auth_passtoken) == ("basic", USER, TOKEN)
    assert any(
        "plain HTTP" in w for w in s.warnings
    )  # HTTP on by default -> warning only
    s = settings(AUTH_MODE="BEARER", AUTH_PASSTOKEN=TOKEN, AUTH_USER="ignored")
    assert s.auth_mode == "bearer" and any(
        "AUTH_USER is ignored" in w for w in s.warnings
    )
    s = settings(AUTH_MODE="basic", AUTH_USER=USER, AUTH_PASSTOKEN="short")
    assert any("shorter than" in w for w in s.warnings)
    s = settings(AUTH_PASSTOKEN=TOKEN)  # mode none: values ignored
    assert (
        s.auth_mode == "none"
        and s.auth_passtoken is None
        and any("ignored" in w for w in s.warnings)
    )


def test_settings_errors():
    expect_exit("AUTH_MODE must be one of", AUTH_MODE="digest")
    expect_exit(
        "needs FEED_DISTRIBUTOR_AUTH_PASSTOKEN", AUTH_MODE="basic", AUTH_USER=USER
    )
    expect_exit(
        "needs FEED_DISTRIBUTOR_AUTH_USER", AUTH_MODE="basic", AUTH_PASSTOKEN=TOKEN
    )
    expect_exit("needs FEED_DISTRIBUTOR_AUTH_PASSTOKEN", AUTH_MODE="bearer")
    expect_exit(
        "cannot contain ':'", AUTH_MODE="basic", AUTH_USER="a:b", AUTH_PASSTOKEN=TOKEN
    )
    expect_exit(
        "Bearer token cannot carry",
        AUTH_MODE="bearer",
        AUTH_PASSTOKEN="has space inside!!",
    )


if __name__ == "__main__":
    tests = [
        (n, f)
        for n, f in sorted(globals().items())
        if n.startswith("test_") and callable(f)
    ]
    for name, func in tests:
        func()
        print(f"ok  {name}")
    print(f"{len(tests)} feed auth checks passed")
