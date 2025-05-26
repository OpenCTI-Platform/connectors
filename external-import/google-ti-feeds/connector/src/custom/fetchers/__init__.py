"""Fetchers package for Google Threat Intelligence API.

This package provides a generic fetcher architecture for different types of entities
from the Google Threat Intelligence API, including reports, malware families,
threat actors, attack techniques, and vulnerabilities.

The package uses a factory pattern with configurable generic fetchers to eliminate
code duplication while maintaining flexibility and performance.
"""

from .base_fetcher import BaseFetcher
from .entity_config import ENTITY_CONFIGS, EntityFetcherConfig
from .entity_fetcher import EntityFetcher
from .fetcher_factory import FetcherFactory
from .generic_entity_fetcher import GenericEntityFetcher
from .relationship_fetcher import RelationshipFetcher
from .report_fetcher import ReportFetcher

__all__ = [
    "BaseFetcher",
    "RelationshipFetcher",
    "ReportFetcher",
    "EntityFetcher",
    "GenericEntityFetcher",
    "EntityFetcherConfig",
    "FetcherFactory",
    "ENTITY_CONFIGS",
]
