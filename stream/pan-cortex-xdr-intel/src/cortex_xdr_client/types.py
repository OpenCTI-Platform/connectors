from typing import Literal, NotRequired, TypedDict


class IocPayload(TypedDict):
    """Caller-facing input for a single IOC, passed to `insert_iocs`.

    Only `indicator` and `type` are required. Other fields may be omitted;
    `insert_iocs` defaults them to `None` (and derives
    `default_expiration_enabled` from `expiration_date`) before sending the
    request, since the Cortex XDR API requires every field to be present in
    the request body.

    References:
      - https://cortex-docs.paloaltonetworks.com/xdr-5-api/cortex-platform/iocs#post-public_api-v1-indicators-insert
    """

    # Existing IOC's Cortex XDR-assigned numeric identifier.
    # Present only when updating an existing IOC; unset when creating a new one.
    rule_id: NotRequired[int | None]

    indicator: str
    type: Literal["HASH", "IP", "PATH", "DOMAIN_NAME", "FILENAME", "MIXED"]
    severity: NotRequired[
        Literal["SEV_010_INFO", "SEV_020_LOW", "SEV_030_MEDIUM", "SEV_040_HIGH"] | None
    ]
    expiration_date: NotRequired[int | None]
    comment: NotRequired[str | None]
    reputation: NotRequired[
        Literal["GOOD", "BAD", "SUSPICIOUS", "UNKNOWN", "NO_REPUTATION"] | None
    ]
    reliability: NotRequired[Literal["A", "B", "C", "D"] | None]


class IocFilter(TypedDict):
    """Caller-facing input for a single filter, passed to `get_iocs` or
    `delete_iocs`.

    Only `value` is required. `field` and `operator` may be omitted; see
    each method's own docstring for its specific default (if any).

    References:
      - https://cortex-docs.paloaltonetworks.com/xdr-5-api/cortex-platform/iocs#post-public_api-v1-indicators-get
      - https://cortex-docs.paloaltonetworks.com/xdr-5-api/cortex-platform/iocs#post-public_api-v1-indicators-delete
    """

    field: NotRequired[Literal["indicator"]]
    operator: NotRequired[Literal["EQ", "NEQ", "IN"]]
    value: str | list[str]  # when `value` is a list, `operator` must be "IN"
