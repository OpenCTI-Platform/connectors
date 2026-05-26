"""Utility helpers used for CI coverage rule validation."""


def build_probe_payload(document_name: str, source: str) -> dict:
    """Return a deterministic payload for manual coverage-gating tests."""
    normalized_name = document_name.strip().lower()
    normalized_source = source.strip().lower()

    return {
        "document_name": normalized_name,
        "source": normalized_source,
        "probe_key": f"{normalized_source}:{normalized_name}",
    }
