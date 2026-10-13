"""Typed models for what the HoneyLabs TAXII 2.1 server returns.

These describe the raw objects, validated at the network boundary. STIX
conversion for OpenCTI happens in the processor.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class TaxiiCollection(BaseModel):
    id: str
    title: str
    alias: str | None = None
    can_read: bool = False


class KillChainPhaseRef(BaseModel):
    kill_chain_name: str
    phase_name: str


class ExternalReferenceRef(BaseModel):
    source_name: str
    url: str | None = None
    description: str | None = None


class TaxiiIndicator(BaseModel):
    """A STIX 2.1 indicator as HoneyLabs serves it: one address or URL, with
    the evidence summarised in the description and a link back to the report."""

    id: str
    name: str
    pattern: str
    pattern_type: str = "stix"
    description: str | None = None
    indicator_types: list[str] = Field(default_factory=list)
    valid_from: datetime
    valid_until: datetime | None = None
    created: datetime
    modified: datetime
    confidence: int | None = None
    labels: list[str] = Field(default_factory=list)
    kill_chain_phases: list[KillChainPhaseRef] = Field(default_factory=list)
    external_references: list[ExternalReferenceRef] = Field(default_factory=list)


class TaxiiEnvelope(BaseModel):
    objects: list[dict] = Field(default_factory=list)
    more: bool = False
    next: str | None = None


class TaxiiPage(BaseModel):
    """One page of a collection: its indicators and the server's own
    `date_added` of the last object on the page (the `X-TAXII-Date-Added-Last`
    header), which is the value a later `added_after` poll must resume from."""

    objects: list[TaxiiIndicator] = Field(default_factory=list)
    date_added_last: datetime | None = None
