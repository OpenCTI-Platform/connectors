"""FalconPy BaseDictionary object.

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
from typing import ItemsView, Any, Union, Dict, List, Optional
import sys
from ._response_component import ResponseComponent


# I live here for now to prevent a circular reference
class UnsupportedPythonVersion(Exception):
    """This feature is not supported by your version of Python."""

    message = "This feature is not supported by your current version of Python."
    code = 426


class BaseDictionary(ResponseComponent):
    """This class represents a dictionary component of an API response."""

    #  _______ _______ _______ _     _  _____  ______  _______
    #  |  |  | |______    |    |_____| |     | |     \ |______
    #  |  |  | |______    |    |     | |_____| |_____/ ______|
    #
    # Convert this object into an iterator by adding iteration
    # handling that leverages our underlying _data dictionary.
    def __init__(self,
                 data: Optional[Dict[str, Union[str, Dict[str, Union[str, dict, list]], List[Union[str, int, dict]]]]] = None
                 ):
        """Construct an instance of the BaseDictionary."""
        super().__init__()
        if data:
            self._data = data
        else:
            self._data = {}

    def __iter__(self):
        """Iterate for the data dictionary."""
        return self._data.__iter__()

    def __next__(self):
        """Get the next item from the data dictionary."""
        _returned = None
        if self.data:
            _returned = next(self.__iter__())
        else:
            raise StopIteration

        return _returned

    def __getitem__(self, pos):
        """Retrieve an item by position from the data dictionary."""
        return self._data.__getitem__(pos)

    def __reversed__(self):
        """Reverse the iteration order."""
        if sys.version_info.minor <= 7:  # pragma: no cover
            raise UnsupportedPythonVersion
        return self._data.__reversed__()

    def __len__(self) -> int:
        """Retrieve the length of the data dictionary."""
        return len(self._data)

    def items(self) -> ItemsView[Any, Any]:
        """Provide expanded dictionary iteration functionality to the class."""
        return self._data.items()

    #   _____   ______  _____   _____  _______  ______ _______ _____ _______ _______
    #  |_____] |_____/ |     | |_____] |______ |_____/    |      |   |______ |______
    #  |       |    \_ |_____| |       |______ |    \_    |    __|__ |______ ______|
    #
    @property
    def data(self) -> Dict[str, Union[str,
                                      Dict[str, Union[str, dict, list]],
                                      List[Union[str, int, dict]]
                                      ]]:
        """Return the contents of the _data attribute as a dictionary."""
        return dict(self._data)
