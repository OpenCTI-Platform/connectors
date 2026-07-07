"""Registry mapping data-source names to their collection callables.

Replaces the old ``DataSource`` enum. Crucially, this is the *only* module that
imports the individual source modules; nothing imports it back, so the source
modules are free to import the client/converter/settings for type hints without
creating an import cycle.
"""

from dataclasses import dataclass
from typing import Callable

from connector.sources import names
from connector.sources.botnets import collect_botnets
from connector.sources.epss import collect_epss
from connector.sources.exploits import collect_exploits
from connector.sources.initial_access import collect_initial_access
from connector.sources.ipintel import collect_ipintel
from connector.sources.nistnvd2 import collect_nistnvd2
from connector.sources.ransomware import collect_ransomware
from connector.sources.snort import collect_snort
from connector.sources.suricata import collect_suricata
from connector.sources.threat_actors import collect_threat_actors
from connector.sources.vckev import collect_vckev
from connector.sources.vcnvd2 import collect_vcnvd2


@dataclass(frozen=True)
class SourceSpec:
    """Describes one configurable data source."""

    name: str
    collect: Callable[..., None]
    api_prefix: str


SOURCES: dict[str, SourceSpec] = {
    spec.name: spec
    for spec in (
        SourceSpec(names.BOTNETS, collect_botnets, names.INDEX_URL_PREFIX),
        SourceSpec(names.EPSS, collect_epss, names.INDEX_URL_PREFIX),
        SourceSpec(names.EXPLOITS, collect_exploits, names.INDEX_URL_PREFIX),
        SourceSpec(
            names.INITIAL_ACCESS, collect_initial_access, names.INDEX_URL_PREFIX
        ),
        SourceSpec(names.IPINTEL, collect_ipintel, names.INDEX_URL_PREFIX),
        SourceSpec(names.NIST_NVD2, collect_nistnvd2, names.INDEX_URL_PREFIX),
        SourceSpec(names.RANSOMWARE, collect_ransomware, names.INDEX_URL_PREFIX),
        SourceSpec(names.SNORT, collect_snort, names.RULES_URL_PREFIX),
        SourceSpec(names.SURICATA, collect_suricata, names.RULES_URL_PREFIX),
        SourceSpec(names.THREAT_ACTORS, collect_threat_actors, names.INDEX_URL_PREFIX),
        SourceSpec(names.VULNCHECK_KEV, collect_vckev, names.INDEX_URL_PREFIX),
        SourceSpec(names.VULNCHECK_NVD2, collect_vcnvd2, names.INDEX_URL_PREFIX),
    )
}


def resolve(configured: list[str], logger=None) -> list[SourceSpec]:
    """Resolve configured source names to their specs.

    Raises ``ValueError`` for an unknown name. ``vulncheck-nvd2`` is an enriched
    superset of ``nist-nvd2`` (same CVEs plus attack patterns, mitigations, data
    sources and CPEs), so when both are configured ``nist-nvd2`` is dropped.
    """
    specs: list[SourceSpec] = []
    for name in configured:
        spec = SOURCES.get(name)
        if spec is None:
            raise ValueError(f"Unknown Data Source name: {name}")
        specs.append(spec)

    selected = {spec.name for spec in specs}
    if names.VULNCHECK_NVD2 in selected and names.NIST_NVD2 in selected:
        specs = [spec for spec in specs if spec.name != names.NIST_NVD2]
        if logger is not None:
            logger.warning(
                "[CONNECTOR] Both vulncheck-nvd2 and nist-nvd2 are configured; "
                "preferring vulncheck-nvd2 and skipping nist-nvd2 (redundant)."
            )

    return specs
