import sys
from pathlib import Path

# Add connector src/ to sys.path so `src.*` imports resolve.
_src_root = Path(__file__).resolve().parent.parent / "src"
if str(_src_root) not in sys.path:
    sys.path.insert(0, str(_src_root.parent))


# ---------------------------------------------------------------------------
# Shared test data factories
# ---------------------------------------------------------------------------


def make_vulnerability(cve_id: str, *, with_cpe: bool = True) -> dict:
    """Return a minimal NVD-style vulnerability dict."""
    vuln = {
        "cve": {
            "id": cve_id,
            "descriptions": [{"value": f"Description of {cve_id}"}],
            "published": "2024-01-15T10:00:00.000",
            "lastModified": "2024-02-01T12:00:00.000",
            "references": [],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "availabilityImpact": "NONE",
                        },
                    }
                ]
            },
            "weaknesses": [],
        }
    }
    return vuln


def make_cpe_name(
    vendor: str = "vendor", product: str = "product", version: str = "1.0"
) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
