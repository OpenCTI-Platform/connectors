"""Logging Class.

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
from logging import Logger
from typing import Optional
from .._constant import MAX_DEBUG_RECORDS


class LogFacility:
    """This class encapsulates the log facility and additional configuration."""

    _file_log: int = 0

    def __init__(self,
                 log: Optional[Logger] = None,
                 debug_record_count: Optional[int] = None,
                 sanitize_log: Optional[bool] = None
                 ):
        """Construct an instance of the LogFacility class."""
        self._log: Optional[Logger] = None
        if isinstance(log, Logger):
            self._log = log

        self._debug_record_count: int = MAX_DEBUG_RECORDS
        if isinstance(debug_record_count, (int, str)):
            self._debug_record_count = int(debug_record_count)

        self._sanitize: bool = True
        if isinstance(sanitize_log, bool):
            self._sanitize = sanitize_log

    def deactivate_log(self):
        """Deactivate the log by removing it from the facility."""
        self._log = None  # Elvis has left the building!

    @property
    def log(self) -> Optional[Logger]:
        """Return our immutable logger."""
        return self._log

    @property
    def active(self) -> bool:
        """Return if logging is active within this facility."""
        return bool(self.log)

    # Mutable
    @property
    def sanitize_log(self) -> bool:
        """Return if sanitization is enabled."""
        return self._sanitize

    @sanitize_log.setter
    def sanitize_log(self, value: bool):
        """Set the log sanitization flag."""
        self._sanitize = value

    @property
    def debug_record_count(self) -> int:
        """Return the current debug record count setting."""
        return self._debug_record_count

    @debug_record_count.setter
    def debug_record_count(self, value: int):
        """Set the debug record count."""
        self._debug_record_count = value

    @property
    def file_log(self) -> int:
        """Integer flag indicating if the log is writing to a file."""
        return self._file_log

    @file_log.setter
    def file_log(self, value: int):
        """Set the file_log flag."""
        self._file_log = value
