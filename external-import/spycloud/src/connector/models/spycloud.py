from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from typing import Literal, Optional


class BreachCatalog(BaseModel):
    """
    Class for SpyCloud breach catalog.
    """

    model_config: ConfigDict = ConfigDict(extra="ignore", frozen=True)

    id: int = Field(
        description="Numerical breach ID. This number correlates to source_id data point found in breach records.",
    )
    uuid: str = Field(
        description="UUID v4 encoded version of breach ID. This is relevant for users of Firehose, where each deliverable (records file) is named using the breach UUID.",
    )
    title: str = Field(
        description="Breach title. For each ingested breach our security research team documents a breach title. This is only available when we can disclose the breach details, otherwise it will have a generic title.",
    )
    description: str = Field(
        description="Breach description. For each ingested breach our security research team documents a breach description. This is only available when we can disclose the breach details, otherwise it will have a generic description.",
    )
    type: str = Field(
        description="Denotes if a breach is considered public or private. A public breach is one that is easily found on the internet, while a private breach is often exclusive to SpyCloud.",
    )
    num_records: int = Field(
        description="Number of records we parsed and ingested from this particular breach. This is after parsing, normalization and deduplication take place.",
    )
    spycloud_publish_date: datetime = Field(
        description="The date on which we ingested the breached data into our systems. This is the same date on which the data becomes publicly available to our customers.",
    )
    acquisition_date: datetime = Field(
        description="The date on which our security research team first acquired the breached data.",
    )
    assets: dict = Field(
        description="Dictionary field. A mapping of assets to count for this particular breach.",
    )
    confidence: int = Field(
        description="Numerical score representing the confidence in the source of the breach. See list of possible values available here.",
    )
    breach_main_category: str = Field(
        description="Categorizes breach into combolist, breach, or malware."
    )
    breach_category: str = Field(description="Categorizes how the data was breached.")
    sensitive_source: bool = Field(
        description="Indicates whether a breach source is sensitive or not."
    )
    consumer_category: str = Field(
        description="Categorization for consumer product mapping."
    )
    tlp: str = Field(
        description="Traffic light protocol. TLP is a set of designations used to ensure that sensitive information is shared with the appropriate audience.",
    )
    short_title: str = Field(
        description="Shortened version of title field when necessary."
    )

    site: Optional[str] = Field(
        description="Website of breached organization, when available."
    )
    site_description: Optional[str] = Field(
        description="Description of the breached organization, when available."
    )
    breach_date: Optional[datetime] = Field(
        description="The date on which we believe the breach took place."
    )
    public_date: Optional[datetime] = Field(
        description="The date on which this breach was made known to the public. This is usually accompanied by media URLs in media_urls list below.",
    )
    media_urls: Optional[list] = Field(
        description="Array field. List of one or more media URLs referencing the breach in media.",
    )
    combo_list_flag: Optional[str] = Field(
        description="Indicates if the breach is a combo list."
    )
    breached_companies: Optional[list] = Field(
        description="Companies that are allegedly or confirmed to be involved in the data breach.",
    )
    targeted_companies: Optional[list] = Field(
        description="Companies determined to be targeted by the breach."
    )
    targeted_industries: Optional[list] = Field(
        description="General industries determined to be targeted by the breach."
    )
    malware_family: Optional[str] = Field(
        description="Contains the malware family variant of the infostealer. Only optionally present when breach_category is infostealer.",
    )


class BreachRecord(BaseModel):
    """
    Class for SpyCloud breach records.
    Only required fields and those useful for OCTI entities are described here but all extra fields provided by Spycloud API are allowed.
    Extra fields are all optional and _might_ be present in API response.
    See https://spycloud-external.readme.io/sc-data-schema/docs/getting-started#breach-records for fields reference.
    """

    model_config: ConfigDict = ConfigDict(extra="allow", frozen=True)

    document_id: str = Field(
        description="UUID v4 string which uniquely identifies this breach record in our data set."
    )
    source_id: int = Field(
        description="Numerical breach ID. This correlates directly with the id field in Breach Catalog objects."
    )
    spycloud_publish_date: datetime = Field(
        description="The date on which this record was ingested into our systems. In ISO 8601 datetime format. This correlates with spycloud_publish_date field in Breach Catalog objects."
    )
    severity: Literal[2, 5, 20, 25] = Field(
        description="Severity is a numeric code representing severity of a breach record. This can be used in API requests to ensure only Breach Records with plaintext password are returned."
    )

    # TODO: add optional fields during STIX observables implementation
