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
"""Tests for the "datetime_converter" module."""

import datetime
import unittest

from . import datetime_converter


class DatetimeConverterTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.date_time = datetime.datetime(
        2020, 11, 5, 0, 0, 0, 0, tzinfo=datetime.timezone.utc)

  def test_iso8601_datetime_utc(self):
    expected_date_time = self.date_time
    date_time = datetime_converter.iso8601_datetime_utc("2020-11-05T00:00:00Z")
    self.assertEqual(date_time, expected_date_time)

  def test_strftime(self):
    expected_date_time_str = "2020-11-05T00:00:00Z"
    date_time_str = datetime_converter.strftime(self.date_time)
    self.assertEqual(date_time_str, expected_date_time_str)


if __name__ == "__main__":
  unittest.main()
