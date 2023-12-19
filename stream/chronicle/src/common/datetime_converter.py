# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Helper functions to convert ISO 8601 strings into datetime objects.
"""

import datetime
import re


def iso8601_datetime_utc(utc_date_time: str) -> datetime.datetime:
  """Converts an ISO 8601 string ("yyyy-mm-ddThh:mm:ssZ") to a datetime object.

  More details: https://en.wikipedia.org/wiki/ISO_8601

  Args:
    utc_date_time: Date and time in the extended ("T") ISO 8601 format, where
      the time is in UTC ("Z").

  Returns:
    Builtin datetime object with a UTC timezone.

  Raises:
    ValueError: Invalid input value.
  """
  # Work-around fixable issues in user-specified timestamps.
  utc_date_time = re.sub(r"(\d{2}-\d{2}-\d{2})\s+(\d)", r"\1T\2",
                         utc_date_time).upper()
  if utc_date_time[-1] != "Z":
    utc_date_time += "Z"

  # Append the suffix "+0000" in order to produce a timezone-aware UTC datetime,
  # because strptime's "%z" does not recognize the meaning of the "Z" suffix.
  try:
    # Support (but don't require) sub-second parsing, but ignore anything
    # smaller than microseconds.
    utc_date_time = re.sub(r"(\d{6})\d+Z", r"\1Z", utc_date_time)
    return datetime.datetime.strptime(f"{utc_date_time}+0000",
                                      "%Y-%m-%dT%H:%M:%S.%fZ%z")
  except ValueError:
    # No microseconds? No problem, try to parse without them.
    # If there's a different parsing problem, it will surface below too.
    pass

  return datetime.datetime.strptime(f"{utc_date_time}+0000",
                                    "%Y-%m-%dT%H:%M:%SZ%z")


def strftime(utc_date_time: datetime.datetime) -> str:
  """Converts a datetime object to a string with the format "%Y-%m-%dT%H:%M:%SZ".

  Args:
    utc_date_time: Builtin datetime object with a UTC timezone.

  Returns:
    Date and time in the format "%Y-%m-%dT%H:%M:%SZ".

  Raises:
    ValueError: Invalid input value.
  """
  if utc_date_time is None:
    return ""
  return utc_date_time.astimezone(
      datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
