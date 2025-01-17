import re
from ipaddress import IPv4Address
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, PositiveInt

# Definition of the compiled regex to validate the domain and subdomain
domain_regex = re.compile(
    r"^(?=.{1,253}$)(?!-)(xn--)?(?:[A-Za-z0-9À-ÿ-_]{1,63}(?<!-)\.)+(?!-)(xn--)?[A-Za-z0-9À-ÿ-_]{2,63}(?<!-)$"
)


def _check_domain_name(value: str):
    if domain_regex.match(value):
        return value
    raise ValueError(f"Invalid DomainName = {value}")


DomainName = Annotated[str, AfterValidator(_check_domain_name)]


class ReputationScore(BaseModel):
    scores: dict[str, PositiveInt] = Field(
        ...,
        description="Mapping of categories to their reputation scores.",
        examples=[{"P2P": 45, "VPN": 61}, {"P2P": 50}],
    )


class IPReputationModel(BaseModel):
    reputation: dict[IPv4Address, ReputationScore] = Field(
        default_factory=dict,
        description="Correspondence between IPs address, their categories and the scores associated with the categories",
    )


class DomainReputationModel(BaseModel):
    reputation: dict[DomainName, ReputationScore] = Field(
        default_factory=dict,
        description="Correspondence between domains, their categories and the scores associated with the categories",
    )
