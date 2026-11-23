from unittest.mock import MagicMock

from connector.stairwell.client import StairwellAPIError, StairwellClient


def answer(status, body=None, not_found_ok=True):
    """What a `StairwellClient` call returns, or raises, for an HTTP `status`
    and JSON `body`. Status 0 stands for a transport error (no response)."""
    if status == 0:
        raise StairwellAPIError("Stairwell request to /fake failed")
    resp = MagicMock(status_code=status, text="")
    resp.json.return_value = body
    return StairwellClient._decode("/fake", resp, not_found_ok)


def lookup(*responses, not_found_ok=True):
    """A client method answering each `(status, body)` in turn, as `answer`
    does. A single response answers every call."""
    pending = list(responses)

    def call(*_args, **_kwargs):
        if len(responses) == 1:
            return answer(*responses[0], not_found_ok=not_found_ok)
        if not pending:
            raise StopIteration
        return answer(*pending.pop(0), not_found_ok=not_found_ok)

    return MagicMock(side_effect=call)
