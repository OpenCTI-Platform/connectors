"""FalconPy ResponseComponent object.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
`-------'                         `-------'

OAuth2 API - Customer SDK

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""
from typing import Union, Optional


class ResponseComponent:
    """Base class for all response object derivatives."""

    #  _______  _____  __   _ _______ _______  ______ _     _ _______ _______  _____   ______
    #  |       |     | | \  | |______    |    |_____/ |     | |          |    |     | |_____/
    #  |_____  |_____| |  \_| ______|    |    |    \_ |_____| |_____     |    |_____| |    \_
    #
    # Sets the data attribute upon creation.
    def __init__(self, data: Optional[Union[dict, bytes, list, str]] = None):
        """Construct an instance of the class and set the private data attribute."""
        # All response components maintain an underlying data attribute.
        # Due to the dynamic types of responses received from the API,
        # this base element is defined as generically as possible.
        self._data: Optional[Union[dict, bytes, list, str, int, float]] = None
        if isinstance(data, (dict, bytes, list, str, int, float)):
            self._data = data

    #  _______ _______ _______ _     _  _____  ______  _______
    #  |  |  | |______    |    |_____| |     | |     \ |______
    #  |  |  | |______    |    |     | |_____| |_____/ ______|
    #
    def __repr__(self) -> str:
        """Return a clean string representation of the underlying data dictionary."""
        return str(self._data)

    def get_property(self, item, default_return: Union[str, int, dict, float, list] = None):
        """Property lookup helper. Returns None if the underlying data is binary."""
        _returned = None
        if isinstance(self._data, dict):
            _returned = self._data.get(item, default_return)
        elif isinstance(self._data, (list, str)):
            try:
                _returned = self._data[item]
            except IndexError as bad_pos:
                raise IndexError(
                    "Invalid position specified. Please check your index and try again."
                    ) from bad_pos

        return _returned

    #   _____   ______  _____   _____  _______  ______ _______ _____ _______ _______
    #  |_____] |_____/ |     | |_____] |______ |_____/    |      |   |______ |______
    #  |       |    \_ |_____| |       |______ |    \_    |    __|__ |______ ______|
    #
    @property
    def data(self) -> Optional[Union[dict, bytes, list, str, int, float]]:
        """Property to reflect the contents of the private _data attribute."""
        return self._data

    @property
    def binary(self) -> bool:
        """Return a boolean indicating if this component represents a binary response."""
        return isinstance(self._data, bytes)
