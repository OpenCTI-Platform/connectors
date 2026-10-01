from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from virustotal.builder import VirusTotalBuilder

if TYPE_CHECKING:
    from virustotal import VirusTotalConnector


class EntityProcessor(ABC):
    """Template-method base class for all VT enrichment processors.

    Subclasses implement ``_fetch_data`` (API call + any upload/retry
    logic) and ``_enrich`` (builder method calls specific to their type).
    Everything else — response validation, builder construction and bundle
    dispatch — is handled here once.
    """

    # VirusTotal endpoint path segment for this entity type (e.g.
    # "ip_addresses"), used to fetch GTI collection relationships. Set by
    # each subclass.
    _GTI_ENDPOINT_TYPE: str = ""

    # Maps each GTI collection relationship to the connector config flag
    # gating it and the VirusTotalBuilder method that builds it. Shared
    # across all entity types since VirusTotal/GTI exposes the same four
    # relationships (malware_families, threat_actors, campaigns, reports)
    # uniformly on IP, domain, URL, and file objects.
    _GTI_RELATIONSHIPS: dict[str, tuple[str, str]] = {
        "malware_families": ("gti_include_malware_families", "create_malware_family"),
        "threat_actors": ("gti_include_threat_actors", "create_intrusion_set"),
        "campaigns": ("gti_include_campaigns", "create_campaign"),
        "reports": ("gti_include_reports", "create_report"),
    }

    def __init__(
        self,
        connector: "VirusTotalConnector",
        stix_objects: list,
        stix_entity: dict,
        opencti_entity: dict,
        is_indicator: bool = False,
    ) -> None:
        self.connector = connector
        self.helper = connector.helper
        self.client = connector.client
        self.stix_objects = stix_objects
        self.stix_entity = stix_entity
        self.opencti_entity = opencti_entity
        self.is_indicator = is_indicator

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self) -> str | None:
        """Run the full enrichment pipeline and return the send result.

        Returns ``None`` when there is nothing to enrich (e.g. an Artifact
        that VT has never seen and has no uploaded file bytes available).
        """
        json_data = self._fetch_data()
        if json_data is None:
            return None
        self._check_response(json_data)
        builder = self._make_builder(json_data)
        self._enrich(builder, json_data)
        self._enrich_gti_relationships(builder)
        return builder.send_bundle()

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _check_response(self, json_data: dict | None) -> None:
        """Raise ``ValueError`` for empty or error responses."""
        if not json_data:
            raise ValueError("[VirusTotal] Empty response received from the API.")
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

    def _gti_identifier(self) -> str:
        """Return the identifier to use for GTI relationship lookups.

        Defaults to the observable's value; overridden by FileProcessor
        since files are looked up by hash, not by their raw SCO value.
        """
        return self.opencti_entity["observable_value"]

    def _enrich_gti_relationships(self, builder: VirusTotalBuilder) -> None:
        """Fetch and build any enabled GTI collection relationships.

        For each of malware_families/threat_actors/campaigns/reports whose
        config flag is enabled, fetches the relationship and calls the
        matching VirusTotalBuilder method for every item returned.

        No-ops entirely when the gti_enrichment_enabled master flag is off,
        regardless of the individual gti_include_* flags below.
        """
        if not self.connector.gti_enrichment_enabled:
            return
        identifier = None
        for relationship, (
            flag_name,
            builder_method,
        ) in self._GTI_RELATIONSHIPS.items():
            if not getattr(self.connector, flag_name):
                continue
            if identifier is None:
                identifier = self._gti_identifier()
            response = self.client.get_gti_relationship(
                self._GTI_ENDPOINT_TYPE,
                identifier,
                relationship,
                self.connector.gti_relationship_limit,
            )
            if not response or "data" not in response:
                continue
            for item in response["data"]:
                getattr(builder, builder_method)(item)

    def _make_builder(self, json_data: dict, **kwargs) -> VirusTotalBuilder:
        """Construct a :class:`VirusTotalBuilder` with connector-level settings."""
        return VirusTotalBuilder(
            self.helper,
            self.connector.author,
            self.connector.replace_with_lower_score,
            self.stix_objects,
            self.stix_entity,
            self.opencti_entity,
            json_data["data"],
            include_attributes_in_note=self.connector.include_attributes_in_note,
            is_indicator=self.is_indicator,
            gti_enabled=self.connector.gti_enrichment_enabled,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def _fetch_data(self) -> dict | None:
        """Fetch the VirusTotal API response for this entity type.

        Implementations should also handle upload/retry logic (e.g. for
        unseen artifacts or URLs) and return the *final* response dict.
        """

    @abstractmethod
    def _enrich(self, builder: VirusTotalBuilder, json_data: dict) -> None:
        """Call the appropriate builder methods for this entity type."""
