import re
from ipaddress import IPv4Address
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, PositiveInt

# Definition of the compiled regex to validate the domain and subdomain
# According to RFC 1034 and 1035, the underscore (_) is not permitted.
# Entities in the proofpoint domain name list will be ignored during the process.
domain_regex = re.compile(
    r"^(?!-)(?:[A-Za-z0-9-]{1,63}(?<!-)\.)+(?!-)[A-Za-z0-9-]{2,63}(?<!-)$"
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
