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
"""Tests for the "regions" module."""

import unittest

from common import regions


class RegionsTest(unittest.TestCase):
    def test_url_asia_southeast1(self):
        self.assertEqual(
            regions.url("https://test", "asia-southeast1"),
            "https://asia-southeast1-test",
        )

    def test_url_europe(self):
        self.assertEqual(regions.url("https://test", "europe"), "https://europe-test")

    def test_url_us(self):
        self.assertEqual(regions.url("https://test", "us"), "https://test")


if __name__ == "__main__":
    unittest.main()
