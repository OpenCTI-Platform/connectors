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
"""Tests for the "chronicle_auth" module."""

import os
import tempfile

import unittest
from unittest import mock
from google.oauth2 import service_account

from . import chronicle_auth


class ChronicleAuthTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    fd, self.path = tempfile.mkstemp(suffix=".json", text=True)
    fake_json_credentials = b"""{
        "client_email": "fake-username@fake-project.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.googleapis.com/token",
        "private_key": "
    """
    fake_private_key = b"""-----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDemycWcEiVMMKm
        /S3f8oRkgxVvbi14D0TWFBUPZq9w1nc7L4Udz7NZ8BKC49DuKi1EgwxF8z0Bve5i
        k6UMfb4JeXLkSSQN4Zy5IbZUr9Mm3w0sjIzTeA1JmIqY+r3EbUxeqFjpqc02HW4h
        j0L7Wj2on9KTvMd0zFRCsLLz7KoZyykDKW3jbvDBNx9n3uUNBb+ZriYNbuAWCSlC
        XD8QbVHq3dqFQFpsofHknDX/+UUS7Q85War4Y2qqdV7SwtTdy2LoNHKLLBHU0WMG
        8x6PZueahkO2tipebJN6js4tSxSyk8sYFkU6onZJV91ysE+7QuS0HdhHTYfZSnC5
        zHmJgyHVAgMBAAECggEABWtajsHKCpPG0WDtinuxfG7yiSVyBu+8OcgAYUEbOVCH
        U5ILGBgz4hclpDken4W4V2gnVtaeoBm7IXw9summxD1ILkWXkpzw/1LSSQqExff9
        Lp33Wbic/jMwAJxuHUeZ6d4IWBvxqoUZ5shBlbPzN1U4v68DXhURYhRCLw0OcRVE
        9I3Ohwy6MntjHAkNTvFrYxQBUnCsTKFKwkimn6huhwE8/nrMpYS8H/8DxPFsBprw
        AznRqWWfJ28yVoEzN+J1aIz631zk+LwSqY0m/TJra1uwMQ5J6bYqWlH8pS/UaI4s
        6Lbhukubpi7P03XpP1aHMwCpwcsZ6hGD7XpELDZBgQKBgQD8fF2lgDcX0ksvcgk2
        KKy4dPqwcONfB41lxbIYE9JZRo3hiWsAwQxfbW6Zt6cEdEqOnROw0jcaJhaKD+qf
        d14ciUA+NjeHyE1yJjbytOnO7fx5wlVamHUI0ykFH4NoN+GOI7zt3kLIb20Zvqab
        4Dt5e5qY5s+Mnr2wJVI8k4NcQQKBgQDhtFJ38bz7ehl9prTQ1AaAxAviU3XOBkko
        uDTglE2aoKjc3qoWoX6vT0iamsM3EYYVZxxbqzjSUCrhpSetKdP/NZNN3mtMvFzj
        ODXyhC43Ro3fVe+JvHzdxRtXbSwZ2GLmkbR8oyi7w4pU8rx9+/UfFOoiqcLIGQbb
        N03t8TJwlQKBgB2fVblaHpyb3phVb8E76m/Fwbe7tuFqWGuNU0TB5pb00SaZ4cT3
        4US86RH92wmJv0mWIj5Hm5Fk0JYoIeXNsmv0qmXiJIe4t2ViGGZHVXsirtF2PF9h
        rbF4XMKuHNO4Yq0zgjICNqGfeRRhKtj06OVq3At+YPFlmmm1Jz3WLL5BAoGAQ3hL
        Gs3px2cVjaky7iYjl4SDZPG8Co14ezKto+DRXgLe17+8Kq22GCPkOUtARgr4ARfk
        s0Z44u3SE8fyF2Kkm+rhEOsHOlYokkfwYIHA6wctS/D9fTgaP5U3eigJgeRclD5E
        LOn9ODvY81HopOSXvuXao+gJcRWCJi/fHNz4Tg0CgYEA0ruTbieHIzCjg8C1Sp40
        GBixMpHsZ2ld1OaqQvidYIUL48TutyQhWHaRIqaziSZJBaNIYB73pIQfLdHIi0hx
        3KHskc16JPhKgWLsl9cTP5GAIP2cqvSqBmnbvX+ArSRbqy4v7kxJwKPai+iaFi5H
        1njcNc79W7qohKZshYNUq/0=
        -----END PRIVATE KEY-----
    """
    fake_private_key = fake_private_key.replace(b" " * 4, b"")
    fake_private_key = fake_private_key.replace(b"\n", b"\\n")
    os.write(fd, fake_json_credentials.strip() + fake_private_key + b'"\n}\n')
    os.close(fd)

  @mock.patch.object(service_account.Credentials, "from_service_account_file")
  def test_initialize_http_session(self, mock_from_service_account_file):
    chronicle_auth.initialize_http_session("")
    mock_from_service_account_file.assert_called_once_with(
        str(chronicle_auth.DEFAULT_CREDENTIALS_FILE),
        scopes=chronicle_auth.AUTHORIZATION_SCOPES)

  @mock.patch.object(service_account.Credentials, "from_service_account_file")
  def test_initialize_http_session_with_custom_json_credentials(
      self, mock_from_service_account_file):
    chronicle_auth.initialize_http_session(self.path)
    mock_from_service_account_file.assert_called_once_with(
        self.path, scopes=chronicle_auth.AUTHORIZATION_SCOPES)

  @mock.patch.object(service_account.Credentials, "from_service_account_file")
  def test_initialize_http_session_with_custom_creds_and_scopes(
      self, mock_from_service_account_file):
    scopes = ["https://www.googleapis.com/auth/malachite-ingestion"]
    chronicle_auth.initialize_http_session(self.path, scopes=scopes)
    mock_from_service_account_file.assert_called_once_with(
        self.path, scopes=scopes)

  def tearDown(self):
    os.remove(self.path)
    super().tearDown()


if __name__ == "__main__":
  unittest.main()
