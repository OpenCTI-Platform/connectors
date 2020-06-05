# -*- coding: utf-8 -*-
"""OpenCTI Malpedia connector utilities module."""

import calendar
from datetime import datetime, timezone


def timestamp_to_datetime(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def datetime_utc_now() -> datetime:
    return datetime.now(timezone.utc)


def datetime_utc_epoch_start() -> datetime:
    return timestamp_to_datetime(0)
