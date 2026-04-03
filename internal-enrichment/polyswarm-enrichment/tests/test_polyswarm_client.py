"""Tests for the polyswarm_client SDK wrapper module."""

import polyswarm_api.settings


def test_user_agent_patched():
    """After importing polyswarm_client, the user-agent must contain our prefix."""
    from polyswarm_enrichment import polyswarm_client  # noqa: F401 — import triggers the patch

    ua = polyswarm_api.settings.DEFAULT_USER_AGENT
    assert "opencti_polyswarm_api/" in ua, f"Expected patched UA, got: {ua}"
    assert ua.startswith("opencti_polyswarm_api/"), f"UA should start with our prefix, got: {ua}"


def test_polyswarm_api_importable():
    """PolyswarmAPI class must be importable from polyswarm_client."""
    from polyswarm_enrichment.polyswarm_client import PolyswarmAPI

    assert PolyswarmAPI is not None


def test_polyswarm_exceptions_importable():
    """polyswarm_exceptions module must be importable from polyswarm_client."""
    from polyswarm_enrichment.polyswarm_client import polyswarm_exceptions

    assert hasattr(polyswarm_exceptions, "NoResultsException")
