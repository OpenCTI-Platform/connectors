from typing import Any, ClassVar, Union

from ..core.base import Intel471Stream


class Verity471Stream(Intel471Stream):
    """
    All search endpoints in Verity471 are of 'stream' type.
    """

    size: ClassVar[int]

    @property
    def cursor_name(self) -> str:
        return f"{self.label}_cursor_v471"

    def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
        return api_response.cursor_next

    def _get_initial_history(self):
        # initial history timestamp is saved in OpenCTI instance state
        # to avoid cursor/from mismatch if the timestamp is changed in the config
        # but the cursor is not reset.
        initial_history_key = f"{self.label}_initdate_v471"
        stored_initial_history = self._get_state(initial_history_key)
        if not stored_initial_history:
            stored_initial_history = self.initial_history
            self._set_state(initial_history_key, stored_initial_history)
        return stored_initial_history

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = {"var_from": self._get_initial_history(), "size": type(self).size}
        if cursor:
            kwargs["cursor"] = cursor
        return kwargs

    def _get_offsets(self) -> list[Union[None, int]]:
        return [None]
