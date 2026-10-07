"""Former values of indicators a stream connector could not withdraw yet.

An update that changes the pattern of an indicator withdraws the values of the
former pattern from the vendor. When the vendor refuses, the stream events that
follow only carry the current pattern: a later delete would find nothing, report the
indicator ``removed`` and leave the former values live, with no deployment left to
reconcile them. ``PendingWithdrawals`` keeps them in the connector state for every
later update or delete of the indicator to withdraw them first, and retries them
periodically: a deleted indicator gets no later event.
"""

import functools
import threading
from collections.abc import Callable, Iterable
from typing import Any

from connectors_sdk.connectors.stream.deployment.reconciler import (
    _ConnectorStateGuard,
)

PENDING_WITHDRAWALS_STATE_KEY = "deployment_pending_withdrawals"
"""Key of the connector state holding the former values to withdraw, per indicator."""

PENDING_WITHDRAWALS_RETRY_INTERVAL = 300.0
"""Seconds between two retries of the kept withdrawals."""


class PendingWithdrawals:
    """Former values of indicators the connector could not withdraw from the vendor.

    The values are kept in the connector state, keyed by an id of the indicator the
    connector chooses, next to the stream position pycti stores there: every write
    goes through the state guard of the reconciliation, so neither is rolled back by
    the other writer. A state reset from the platform forgets them. The withdrawals
    of the stream path and of the retries are serialized by ``lock``.
    """

    def __init__(
        self,
        helper: Any,
        retry_interval: float = PENDING_WITHDRAWALS_RETRY_INTERVAL,
    ) -> None:
        """Initialize the store.

        Args:
            helper: The pycti connector helper (``get_state`` and ``set_state``).
            retry_interval: Seconds between two retries of the kept withdrawals.
        """
        self._helper = helper
        self._retry_interval = retry_interval
        self.lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

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
            indicator_id: The id of the indicator.

        Returns:
            The values, in the order they were kept (empty when none is).
        """
        return self._all().get(indicator_id, [])

    def keep(self, indicator_id: str, values: Iterable[str]) -> None:
        """Keep former values of an indicator for its next update or delete.

        Used when the former values stay live on purpose, for instance while a
        failed update leaves the previous version of the indicator on the vendor.

        Args:
            indicator_id: The id of the indicator.
            values: The former values to withdraw later.
        """
        with self.lock:
            kept = self.values(indicator_id)
            added = [value for value in dict.fromkeys(values) if value not in kept]
            if added:
                self._set(indicator_id, kept + added)

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
            indicator_id: The id of the indicator.
            withdraw: Withdraws one value from the vendor, raises when refused.
            values: The former values of the update being processed.

        Raises:
            Exception: The error of the refused withdrawal.
        """
        with self.lock:
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

    def retry_all(self, withdraw: Callable[[str, str], Any]) -> None:
        """Withdraw the kept values of every indicator once. Never raises.

        A refusal keeps the values left for the next retry and is logged.

        Args:
            withdraw: Withdraws one value of an indicator from the vendor (called
                with the indicator id and the value), raises when refused.
        """
        try:
            indicator_ids = list(self._all())
        except Exception as err:  # noqa: BLE001 - retried at the next round
            self._log_retry_failure(None, err)
            return
        for indicator_id in indicator_ids:
            try:
                self.withdraw(indicator_id, functools.partial(withdraw, indicator_id))
            except Exception as err:  # noqa: BLE001 - kept for the next round
                self._log_retry_failure(indicator_id, err)

    def _log_retry_failure(self, indicator_id: str | None, error: Exception) -> None:
        """Log a retry that left kept values."""
        self._helper.connector_logger.warning(
            "[DEPLOYMENT] Former values of an indicator still not withdrawn from the "
            "vendor, retried later.",
            meta={"indicator_id": indicator_id, "error": str(error)},
        )

    def start_retries(self, withdraw: Callable[[str, str], Any]) -> bool:
        """Retry the kept withdrawals every retry interval, in a daemon thread.

        Args:
            withdraw: Withdraws one value of an indicator from the vendor (see
                ``retry_all``).

        Returns:
            ``True`` when the retries run (none with a retry interval of 0).
        """
        if self._retry_interval <= 0:
            return False
        if self._thread is not None and self._thread.is_alive():
            return True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._retry_periodically,
            args=(withdraw,),
            name="deployment-pending-withdrawals",
            daemon=True,
        )
        self._thread.start()
        return True

    def stop_retries(self, timeout: float | None = None) -> None:
        """Stop the periodic retries.

        Args:
            timeout: Seconds to wait for a running retry to finish.
        """
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def _retry_periodically(self, withdraw: Callable[[str, str], Any]) -> None:
        """Retry the kept withdrawals until ``stop_retries()`` is called."""
        while not self._stop_event.wait(self._retry_interval):
            self.retry_all(withdraw)
