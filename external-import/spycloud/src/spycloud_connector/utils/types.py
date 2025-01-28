from typing import Literal

SpycloudSeverityType = Literal[2, 5, 20, 25]
SpycloudWatchlistTypeType = Literal["email", "domain", "subdomain", "ip"]

OCTIIdentityClassType = Literal[
    "individual", "group", "system", "organization", "class", "unknown"
]
OCTISeverityType = Literal["low", "medium", "high", "critical"]
OCTITLPLevelType = Literal["white", "green", "amber", "amber+strict", "red"]
