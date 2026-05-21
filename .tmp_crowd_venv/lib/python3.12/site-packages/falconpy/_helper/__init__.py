"""Helper module.

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
from secrets import choice
from string import ascii_letters, digits
from .._constant import MAX_RANDOM_STRING_LENGTH
from ._text_colors import Color
from ._indicator import Indicator
from ._find_operation import find_operation


def random_string(length: int = 10,
                  include_letters: bool = True,
                  include_digits: bool = True,
                  include_specials: bool = False
                  ):
    """Generate a random string based upon requested character set."""
    character_set = ""
    returned = ""
    character_set = character_set + (ascii_letters if include_letters else "")
    character_set = character_set + (digits if include_digits else "")
    character_set = character_set + ("!@#$%?&*_." if include_specials else "")
    gen_length = max(1, min(length, MAX_RANDOM_STRING_LENGTH))
    if character_set:
        returned = "".join(choice(character_set) for _ in range(gen_length))

    return returned


__all__ = ["Color", "Indicator", "random_string", "find_operation"]
