"""Progress and waiting indicator helper.

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
from typing import List


def _cylon():
    cylons = []
    total = 7
    cylons.append(f"{'o' * (total+1)}")
    for cnt in range(total):
        cylons.append(f"{'o' * (cnt)}O{'o' * (total - cnt)}")
    cylons.append(f"{'o' * (cnt+1)}O")
    cylons.append(f"{'o' * (total+1)}")

    return cylons


class Indicator:
    """Helper to show waiting progress indicators."""

    CLOCK = ["🕛", "🕐", "🕑", "🕒", "🕓", "🕔", "🕧", "🕖", "🕗", "🕘", "🕙", "🕚"]
    MOON = ["🌕", "🌖", "🌗", "🌘", "🌑", "🌒", "🌓", "🌔"]
    KITT = ["........", "o.......", "Oo......", "oOo.....", ".oOo....", "..oOo...",
            "...oOo..", "....oOo.", ".....oOo", "......oO", ".......o", "........"
            ]
    CYLON = _cylon()
    THINKING = ["🤔", "🤔", "🤔", "🤔", "🤔", "  ", "  ", "  ", "  ", "  "]

    def __init__(self, style: str = "moon"):
        """Initialize the class and set the starting position."""
        self._position = -1
        try:
            self._indicator = getattr(self, style.upper())
        except AttributeError:
            self._indicator = self.MOON

    def __repr__(self) -> str:
        """Increment the position and display the current progress indicator value."""
        self.position += 1
        if self.position > len(self.indicator) - 1:
            self.position = 0
        return self.indicator[self.position]

    @property
    def indicator(self) -> List[str]:
        """Progress indicator graphical elements."""
        return self._indicator

    @property
    def position(self) -> int:
        """Progress indicator position."""
        return self._position

    @position.setter
    def position(self, value: int):
        """Set the indicator position."""
        self._position = value
