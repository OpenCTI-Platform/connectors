"""EXAMPLE typed models -- illustrates validating raw API data.

.. important::
    `Report` and `CVE` below are **worked examples**, not real entity
    types to keep. They describe the shape of the fictional
    `TemplateClient` responses (see `template_client/api_client.py`),
    not any real API. Replace them entirely with one model per entity type
    your own connector actually fetches.

Why this pattern matters, regardless of your own API's shape:
    Defining one Pydantic model per entity type lets your API client
    validate every response as soon as it is received: if the API changes
    its response shape, has an undocumented field type, or returns
    unexpected/missing data, a clear `pydantic.ValidationError` is raised
    right there, at the network boundary -- instead of a confusing error
    later, deep inside the STIX conversion logic, that is much harder to
    trace back to its root cause.

These models describe *raw* data, exactly as returned by the API -- they
are **not** STIX objects. STIX conversion is a separate step, handled in
`connector/data_processors/` (see the `_convert_*` methods there).

Notes:
    To adapt this template to your own connector:
        - [ ] Delete `Report`/`CVE` and add one model per real entity
          type your connector imports (e.g. `Event`, `IOC`).
        - [ ] Field names should match the API's response field names
          exactly, whatever their casing/style (`camelCase`,
          `snake_case`...) -- rename them to something more STIX-friendly
          only later, on the conversion side (in the processors'
          `_convert_*` methods), not here.
        - [ ] Only declare the fields you actually use -- Pydantic ignores
          any extra fields returned by the API by default, so there is no
          need to exhaustively mirror the entire API schema.
        - [ ] Consider whether a field should be required or optional
          (`| None = None`) based on what your API actually guarantees.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class Report(BaseModel):
    """EXAMPLE model -- shape of a fictional `/reports` API response.

    This model exists only to demonstrate the "validate raw data with
    Pydantic" pattern described in this module's docstring. Replace it
    with a model matching one of your own connector's real entity types.
    """

    id: str = Field(description="Unique identifier for the report")
    title: str = Field(description="Title of the report")
    publishedAt: datetime = Field(description="Date when the report was published")
    updatedAt: datetime = Field(description="Date when the report was updated")


class CVE(BaseModel):
    """EXAMPLE model -- shape of a fictional `/cves` API response.

    This model exists only to demonstrate the "validate raw data with
    Pydantic" pattern described in this module's docstring. Replace it
    with a model matching one of your own connector's real entity types.
    """

    cveId: str = Field(description="CVE identifier")
    name: str = Field(description="Common name of the vulnerability")
    cvssVector: str = Field(description="CVSS vector representing the vulnerability")
    cvssScore: str = Field(description="CVSS score of the vulnerability")
