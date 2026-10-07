"""Former values of indicators a stream connector could not withdraw yet.

An update that changes the pattern of an indicator withdraws the values of the
former pattern from the vendor. When the vendor refuses, the stream events that
follow only carry the current pattern: a later delete would find nothing, report the
indicator ``removed`` and leave the former values live, with no deployment left to
reconcile them. ``PendingWithdrawals`` keeps them in the connector state for every
later update or delete of the indicator to withdraw them first.
"""

from collections.abc import Callable, Iterable
from typing import Any

from connectors_sdk.connectors.stream.deployment.reconciler import (
    _ConnectorStateGuard,
)

PENDING_WITHDRAWALS_STATE_KEY = "deployment_pending_withdrawals"
"""Key of the connector state holding the former values to withdraw, per indicator."""


class PendingWithdrawals:
    """Former values of indicators the connector could not withdraw from the vendor.

    The values are kept in the connector state, keyed by the STIX id of the
    indicator, next to the stream position pycti stores there: every write goes
    through the state guard of the reconciliation, so neither is rolled back by the
    other writer. A state reset from the platform forgets them.
    """

    def __init__(self, helper: Any) -> None:
        """Initialize the store.

        Args:
            helper: The pycti connector helper (``get_state`` and ``set_state``).
        """
        self._helper = helper

    def _all(self) -> dict[str, list[str]]:
        """Return the kept values of every indicator, read from the connector state."""
        get_state = getattr(self._helper, "get_state", None)
        state = get_state() if callable(get_state) else None
        pending = (
            state.get(PENDING_WITHDRAWALS_STATE_KEY)
            if isinstance(state, dict)
            else None
        )
        if not isinstance(pending, dict):
            return {}
        return {
            indicator_id: [value for value in values if isinstance(value, str)]
            for indicator_id, values in pending.items()
            if isinstance(indicator_id, str) and isinstance(values, list)
        }

    def _set(self, indicator_id: str, values: list[str]) -> None:
        """Keep the values of an indicator (none forgets the indicator)."""
        if not callable(getattr(self._helper, "set_state", None)):
            return
        pending = self._all()
        if values:
            pending[indicator_id] = values
        else:
            pending.pop(indicator_id, None)
        _ConnectorStateGuard.of(self._helper).update(
            PENDING_WITHDRAWALS_STATE_KEY, pending
        )

    def values(self, indicator_id: str) -> list[str]:
        """Return the former values kept for an indicator.

        Args:
            indicator_id: The STIX id of the indicator.

        Returns:
            The values, in the order they were kept (empty when none is).
        """
        return self._all().get(indicator_id, [])

    def withdraw(
        self,
        indicator_id: str,
        withdraw: Callable[[str], Any],
        values: Iterable[str] = (),
    ) -> None:
        """Withdraw former values of an indicator, kept ones included.

        The values kept by earlier calls are withdrawn first, then ``values``. When
        the vendor refuses one, the values not withdrawn yet are kept for the next
        call and the error is raised.

        Args:
            indicator_id: The STIX id of the indicator.
            withdraw: Withdraws one value from the vendor, raises when refused.
            values: The former values of the update being processed.

        Raises:
            Exception: The error of the refused withdrawal.
        """
        kept = self.values(indicator_id)
        remaining = kept + [
            value for value in dict.fromkeys(values) if value not in kept
        ]
        while remaining:
            try:
                withdraw(remaining[0])
            except Exception:
                self._set(indicator_id, remaining)
                raise
            remaining.pop(0)
        if kept:
            self._set(indicator_id, [])
