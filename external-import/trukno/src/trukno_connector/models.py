from dataclasses import dataclass


@dataclass(slots=True)
class BreachSummary:
    id: str
    updated_at: str
