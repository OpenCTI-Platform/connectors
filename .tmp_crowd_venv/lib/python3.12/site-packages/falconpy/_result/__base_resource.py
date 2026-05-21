"""FalconPy BaseResource object.

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
from typing import List, Optional, Union
from ._response_component import ResponseComponent


class BaseResource(ResponseComponent):
    """The base class for different resource types we can have within an API response."""

    #  _______  _____  __   _ _______ _______  ______ _     _ _______ _______  _____   ______
    #  |       |     | | \  | |______    |    |_____/ |     | |          |    |     | |_____/
    #  |_____  |_____| |  \_| ______|    |    |    \_ |_____| |_____     |    |_____| |    \_
    #
    def __init__(self, data: Optional[List[Union[str, int, float, dict]]] = None):
        """Construct an instance of the class."""
        # Override the _data attribute from ResponseComponent to always be a list.
        self._data: Optional[List[Union[str, int, float, dict]]] = []
        self._pos: int = 0

        if isinstance(data, list):
            super().__init__(data=data)

        # else the Resources branch is present but is a NoneType

    #  _______ _______ _______ _     _  _____  ______  _______
    #  |  |  | |______    |    |_____| |     | |     \ |______
    #  |  |  | |______    |    |     | |_____| |_____/ ______|
    #
    # Helper dunder methods to expose functionality of the underlying _data list attribute.
    def __iter__(self):
        """Return the resource list iterator."""
        return self._data.__iter__()

    def __next__(self):
        """Get the next item in the resources list."""
        _returned = None
        if self.data:
            _returned = next(self.__iter__())
            self._pos += 1
            if self._pos >= len(self.data):
                raise StopIteration
        else:
            raise StopIteration

        return _returned

    def __getitem__(self, pos):
        """Retrieve an item by position from the resources list."""
        return self._data.__getitem__(pos)

    def __reversed__(self):
        """Reverse the iteration order."""
        return self._data.__reversed__()

    def __len__(self) -> int:
        """Return the length of the resource list."""
        return len(self._data)

    #   _____   ______  _____   _____  _______  ______ _______ _____ _______ _______
    #  |_____] |_____/ |     | |_____] |______ |_____/    |      |   |______ |______
    #  |       |    \_ |_____| |       |______ |    \_    |    __|__ |______ ______|
    #
    # Properties within a resource object are immutable once they are created.
    @property
    def data(self) -> List[Optional[Union[str, int, float, dict]]]:
        """Return the contents of the underlying _data attribute."""
        return list(self._data)
