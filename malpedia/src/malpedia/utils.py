# -*- coding: utf-8 -*-
"""OpenCTI Malpedia connector utilities module."""

import calendar
from datetime import datetime, timezone


def datetime_to_timestamp(datetime_value: datetime) -> int:
    # Use calendar.timegm because the time.mktime assumes that the input is in
    # your local timezone.
    return calendar.timegm(datetime_value.timetuple())


def timestamp_to_datetime(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def datetime_utc_now() -> datetime:
    return datetime.now(timezone.utc)


def datetime_utc_epoch_start() -> datetime:
    return timestamp_to_datetime(0)
