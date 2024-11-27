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
"""Support for regional URLs in all Chronicle API calls.

For backward compatibility, the US region is considered as the default.
"""

import argparse

REGION_LIST = (
    "asia-northeast1",
    "asia-south1",
    "asia-southeast1",
    "australia-southeast1",
    "eu",
    "europe",
    "europe-west12",
    "europe-west2",
    "europe-west3",
    "europe-west6",
    "europe-west9",
    "me-central1",
    "me-central2",
    "me-west1",
    "northamerica-northeast2",
    "southamerica-east1",
    "us",
)


def add_argument_region(parser: argparse.ArgumentParser):
    """
    Adds a shared command-line argument to all the sample modules.

    Args:
        parser: the parser to which the argument is added
    """
    parser.add_argument(
        "-r",
        "--region",
        type=str,
        required=False,
        default="us",
        choices=REGION_LIST,
        help="the region where the customer is located (default: us)",
    )


def url(base_url: str, region: str) -> str:
    """
    Returns a regionalized URL based on the default and the given region.

    Args:
        base_url: URL pointing to Chronicle API
        region: region in which the target project is located
    """
    if region != "us":
        base_url = base_url.replace("https://", f"https://{region}-")
    return base_url


def url_always_prepend_region(base_url: str, region: str) -> str:
    """
    Returns a regionalized URL.

    Args:
      base_url: URL pointing to Chronicle API
      region: region in which the target project is located

    Returns:
      A string containing a regionalized URL. Unlike the url() function,
      this function always prepends region; this function also checks whether
      the URL already has the region prefix, and if so, returns the URL unchanged.
      v1alpha samples should use this function.
    """
    if not base_url.startswith(f"https://{region}-"):
        base_url = base_url.replace("https://", f"https://{region}-")
    return base_url