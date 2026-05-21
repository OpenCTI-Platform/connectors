r"""FalconPy Uber Class module.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
`-------'                         `-------'

The
   __ __  ____     ___  ____          __  _       ____  _____ _____
  |  T  T|    \   /  _]|    \        /  ]| T     /    T/ ___// ___/
  |  |  ||  o  ) /  [_ |  D  )      /  / | |    Y  o  (   \_(   \_
  |  |  ||     TY    _]|    /      /  /  | l___ |     |\__  T\__  T
  |  :  ||  O  ||   [_ |    \     /   \_ |     T|  _  |/  \ |/  \ |
  l     ||     ||     T|  .  Y    \     ||     ||  |  |\    |\    |
   \__,_jl_____jl_____jl__j\_j     \____jl_____jl__j__j \___j \___j

   for the CrowdStrike OAuth2 API Customer SDK

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
from ._legacy import APIHarness
from ._advanced import APIHarnessV2

__all__ = ["APIHarness", "APIHarnessV2"]
