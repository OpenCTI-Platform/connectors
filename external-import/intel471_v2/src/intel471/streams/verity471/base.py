from typing import Any, ClassVar, Union
from ..core.base import Intel471Stream


class Verity471Stream(Intel471Stream):
    """
    All search endpoints in Verity471 are of 'stream' type.
    """
    initial_history_key: ClassVar[str]

    def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
        return api_response.cursor_next

    def _get_initial_history(self):
        # initial history timestamp is saved in OpenCTI instance state
        # to avoid cursor/from mismatch if the timestamp is changed in the config
        # but the cursor is not reset.
        initial_history_key = type(self).initial_history_key
        stored_initial_history = self._get_state(initial_history_key)
        if not stored_initial_history:
            stored_initial_history = self.initial_history
            self._set_state(initial_history_key, stored_initial_history)
        return stored_initial_history

    def _get_offsets(self) -> list[Union[None, int]]:
        return [None]
