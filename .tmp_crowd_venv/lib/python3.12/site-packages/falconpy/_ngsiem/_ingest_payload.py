"""CrowdStrike NGSIEM API HEC payload.

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
import re
from csv import DictWriter
from datetime import datetime, timezone
from io import StringIO
from inspect import getmembers
from json import dumps
from typing import Dict, Union
from .._enum import TimeUnit


class IngestPayload:
    """Class to represent a JSON formatted ingest payload."""

    _host: str = None
    _timestamp: int = None
    _timeunit: str = None
    _custom: Dict[str, Union[str, int, dict, list]] = {}
    _fields: Dict[str, Union[str, int, dict, list]] = {}

    def __init__(self,
                 host: str = None,
                 timestamp: int = None,
                 timeunit: str = None,
                 custom: Dict[str, Union[str, int, dict, list]] = None,
                 fields: Dict[str, Union[str, int, dict, list]] = None,
                 **kwargs
                 ):
        """Create an instance of the class."""
        if host:
            self.host = host
        if timestamp:
            self.timestamp = timestamp
        if timeunit:
            self.timeunit = timeunit
        if custom:
            self.custom = custom
        else:
            self.custom = {}
        if fields:
            self.fields = fields
        for provided_key, provided_value in kwargs.items():
            if provided_key not in [key[0] for key in getmembers(self) if "_" not in key[0]]:
                self.custom[provided_key] = provided_value

    def to_json(self, raw: bool = False, nowrap: bool = False) -> Union[Dict[str, Union[str, int, dict, list]], str]:
        """Convert the class to a JSON compliant dictionary or JSON string."""
        returned = {}
        items = [key[0] for key in getmembers(self) if "_" not in key[0]]
        event = {
            item_key: getattr(self, item_key)
            for item_key in items if item_key not in ["fields", "custom", "timeunit"]
        }
        for unit in TimeUnit:
            if unit.value == self.timeunit:
                event["timeunit"] = unit.name.lower()
        for key, value in self.custom.items():
            event[key] = value

        returned["event"] = event
        if not raw:
            # Raw payloads cannot specify the fields dictionary
            if getattr(self, "fields"):
                returned["fields"] = self.fields

        if nowrap:
            returned = returned["event"]

        if raw:
            # Convert to a JSON string for raw payloads
            returned = dumps(returned)

        return returned

    def to_xml(self, raw: bool = False, nowrap: bool = False) -> str:
        """Convert the class to XML."""
        returned = ""
        fields = ""
        start_items = [key[0] for key in getmembers(self) if "_" not in key[0]]
        items = []
        for item in start_items:
            if item not in ["timeunit", "fields", "custom"]:
                if item:
                    items.append(item)
        for item in items:
            text = re.sub(r"['\[\]]", "", str(getattr(self, item)))
            returned = f"{returned}<{item}>{text}</{item}>"
        for unit in TimeUnit:
            if unit.value == self.timeunit:
                returned = f"{returned}<timeunit>{unit.name.lower()}</timeunit>"
        for key, value in self.custom.items():
            text = re.sub(r"['\[\]]", "", str(value))
            returned = f"{returned}<{key}>{text}</{key}>"
        if not raw:
            for key, value in self.fields.items():
                text = re.sub(r"['\[\]]", "", str(value))
                fields = f"<fields><{key}>{text}</{key}></field>"
        if not nowrap:
            returned = f"<event>{returned}</event>"
            returned = f"{returned}{fields}"

        return returned

    def to_csv(self) -> str:
        """Convert the class to CSV."""
        # CSV only provides raw content, and does not support event wrapping or additional fields.
        start_items = [key[0] for key in getmembers(self) if "_" not in key[0]]
        items = []
        for item in start_items:
            if item not in ["fields", "custom"]:
                if item:
                    items.append(item)
        returned = StringIO()
        writer = DictWriter(returned, fieldnames=items)
        row = {item: getattr(self, item) for item in items}
        # for key, value in row.items():
        #     if isinstance(value, list):
        #         new_value = re.sub(r"['\[\]]", "", str(value)).replace(",", "~")
        #         row[key] = new_value
        for unit in TimeUnit:
            if unit.value == self.timeunit:
                row["timeunit"] = unit.name.lower()
        for key, value in self.custom.items():
            new_value = re.sub(r"['\[\]]", "", str(value)).replace(",", "~")
            row[key] = new_value
            items.append(key)

        writer.writeheader()
        writer.writerow(row)

        return returned.getvalue()

    @property
    def host(self) -> str:
        """Return the host property."""
        return self._host

    @host.setter
    def host(self, value: str):
        """Set the host property."""
        self._host = value

    @property
    def timeunit(self) -> int:
        """Return the timestamp time unit."""
        if not self._timeunit:
            self._timeunit = TimeUnit["NANOSECONDS"].value
        return self._timeunit

    @timeunit.setter
    def timeunit(self, value: str):
        self._timeunit = TimeUnit[value.upper()].value

    @property
    def timestamp(self) -> int:
        """Return the timestamp property."""
        if not self._timestamp:
            self._timestamp = int(datetime.now(timezone.utc).timestamp() * self.timeunit)
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value: int):
        """Set the timestamp property."""
        self._timestamp = value

    @property
    def custom(self) -> Dict[str, Union[str, int, dict, list]]:
        """Return the custom properties."""
        return self._custom

    @custom.setter
    def custom(self, value: Dict[str, Union[str, int, dict, list]]):
        """Set the custom properties."""
        self._custom = value

    @property
    def fields(self) -> Dict[str, Union[str, int, dict, list]]:
        """Return the fields dictionary."""
        return self._fields

    @fields.setter
    def fields(self, value: Dict[str, Union[str, int, dict, list]]):
        """Set the fields dictionary."""
        self._fields = value
