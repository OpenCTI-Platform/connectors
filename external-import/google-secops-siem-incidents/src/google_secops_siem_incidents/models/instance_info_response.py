"""Pydantic v2 model for the Chronicle Instance Info response."""

from pydantic import BaseModel, ConfigDict, Field


class InstanceInfoResponse(BaseModel):
    """Response from GET /v1alpha/{instance_path} — describes a Chronicle instance."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(description="Full resource name of the instance.")
    state: str = Field(default="", description="Instance state (e.g. 'ACTIVE').")
    display_name: str = Field(
        default="", alias="displayName", description="Human-readable instance name."
    )
    secops_urls: list[str] = Field(
        default_factory=list,
        alias="secopsUrls",
        description="List of SecOps UI base URLs for this instance.",
    )
