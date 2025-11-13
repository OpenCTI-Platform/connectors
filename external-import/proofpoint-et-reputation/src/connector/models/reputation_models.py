import re
from ipaddress import IPv4Address
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, PositiveInt

# Definition of the compiled regex to validate the domain and subdomain
domain_regex = re.compile(
    r"^(?=.{1,253}$)(?!-)(xn--)?(?:[A-Za-z0-9À-ÿ-_]{1,63}(?<!-)\.)+(?!-)(xn--)?[A-Za-z0-9À-ÿ-_]{2,63}(?<!-)$"
)


def _check_domain_name(value: str) -> str:
    """
    Checks if the given value is a valid domain name.

    Args:
        value (str): The domain name to validate.

    Returns:
        str: The valid domain name if it matches the regex pattern.

    Notes:
        regex : "^(?=.{1,253}$)(?!-)(xn--)?(?:[A-Za-z0-9À-ÿ-_]{1,63}(?<!-)\.)+(?!-)(xn--)?[A-Za-z0-9À-ÿ-_]{2,63}(?<!-)$"
    """
    if domain_regex.match(value):
        return value
    raise ValueError(f"The provided value '{value}' is not a valid domain name.")


DomainName = Annotated[str, AfterValidator(_check_domain_name)]


class BaseReputation(BaseModel):
    """Represent the BaseReputation model."""

    value: str
    score_by_category: dict[str, PositiveInt] = Field(
        ...,
        description="Mapping of categories to their reputation scores.",
        examples=[{"P2P": 45, "VPN": 61}, {"P2P": 50}],
    )


class IPReputationModel(BaseReputation):
    """Represent an extent the BaseReputation model by specifying the `value` as an ipv4 address."""

    value: IPv4Address = Field(
        ...,
        description="The IP address for which the reputation score and categories are assigned.",
    )


class DomainReputationModel(BaseReputation):
    """Represent an extent the BaseReputation model by specifying the `value` as a domain name."""

    value: DomainName = Field(
        ...,
        description="The domain name for which the reputation score and categories are assigned.",
    )
