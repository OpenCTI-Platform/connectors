from enum import Enum
from typing import Union

# Bounds of the epoch range recognised for initial-history timestamps, given as
# seconds; the millisecond bounds are the same numbers scaled by 1000. They are wide
# on purpose (2000-01-01 .. 2100-01-01) - the point is not to police the date, only
# to tell the two units apart, which works because the ranges cannot overlap: the
# largest value accepted as seconds is three orders of magnitude below the smallest
# value accepted as milliseconds.
MIN_EPOCH_SECONDS = 946_684_800  # 2000-01-01T00:00:00Z
MAX_EPOCH_SECONDS = 4_102_444_800  # 2100-01-01T00:00:00Z


def coerce_epoch_millis(value: Union[int, None]) -> Union[int, None]:
    """
    Return `value` expressed in epoch milliseconds, or `None` if it is plausible
    neither as epoch milliseconds nor as epoch seconds.

    The APIs expect milliseconds, so a timestamp handed over in seconds is read as a
    date in early 1970, which silently turns "fetch from last month" into "fetch the
    entire history". Callers use this to spot that case and scale the value up.
    """
    if not isinstance(value, int):
        return None
    if MIN_EPOCH_SECONDS * 1000 <= value <= MAX_EPOCH_SECONDS * 1000:
        return value
    if MIN_EPOCH_SECONDS <= value <= MAX_EPOCH_SECONDS:
        return value * 1000
    return None


class HelperRequest:
    class Operation(Enum):
        GET = "get"
        UPDATE = "update"
        KILL = "kill"

    def __init__(
        self, operation: Operation, stream: str = None, data: dict = None
    ) -> None:
        self.stream = stream
        self.operation = operation
        self.data = data

    def __repr__(self) -> str:
        return f"HelperRequest<stream={self.stream}, operation={self.operation}, data={str(self.data)}>"
