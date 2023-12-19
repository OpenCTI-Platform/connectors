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
"""Helper functions to access Chronicle APIs using OAuth 2.0.

Background information:

https://google-auth.readthedocs.io/en/latest/user-guide.html#service-account-private-key-files
https://developers.google.com/identity/protocols/oauth2#serviceaccount

Details about using the Google-auth library with the Requests library:

https://github.com/googleapis/google-auth-library-python/blob/master/google/auth/transport/requests.py
https://requests.readthedocs.io
"""

import argparse
import pathlib
from typing import Optional, Sequence, Union

from google.auth.transport import requests
from google.oauth2 import service_account

DEFAULT_CREDENTIALS_FILE = pathlib.Path.home() / ".chronicle_credentials.json"

AUTHORIZATION_SCOPES = ["https://www.googleapis.com/auth/chronicle-backstory"]


def initialize_http_session(
    credentials_file_path: Optional[Union[str, pathlib.Path]],
    scopes: Optional[Sequence[str]] = None) -> requests.AuthorizedSession:
  """Initializes an authorized HTTP session, based on the given credentials.

  Args:
    credentials_file_path: Absolute or relative path to a JSON file containing
      the private OAuth 2.0 credentials of a Google Cloud Platform service
      account. Optional - the default is ".chronicle_credentials.json" in the
      user's home directory. Keep it secret, keep it safe.
    scopes: A list of OAuth scopes (https://oauth.net/2/scope/) that are
      associated with the end points to be accessed. The default is the
      Chronicle API scope.

  Returns:
    HTTP session object to send authorized requests and receive responses.

  Raises:
    OSError: Failed to read the given file, e.g. not found, no read access
      (https://docs.python.org/library/exceptions.html#os-exceptions).
    ValueError: Invalid file contents.
  """
  credentials = service_account.Credentials.from_service_account_file(
      str(credentials_file_path or DEFAULT_CREDENTIALS_FILE),
      scopes=scopes or AUTHORIZATION_SCOPES)
  return requests.AuthorizedSession(credentials)


def add_argument_credentials_file(parser: argparse.ArgumentParser):
  """Adds a shared command-line argument to all the sample modules."""
  parser.add_argument(
      "-c",
      "--credentials_file",
      type=str,
      help=f"credentials file path (default: '{DEFAULT_CREDENTIALS_FILE}')")
