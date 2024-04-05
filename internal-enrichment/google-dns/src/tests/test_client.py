import unittest

import responses
from src.client import GoogleDNSClient


class GoogleDNSClientTest(unittest.TestCase):
    def setUp(self):
        self.client = GoogleDNSClient()

    @responses.activate
    def test_no_results(self):
        responses.get(
            url="https://dns.google.com/resolve",
            match=[
                responses.matchers.query_param_matcher(
                    {"name": "fake.example.com", "type": "A"}
                )
            ],
            json={},
        )
        results = self.client.a("fake.example.com")
        self.assertEqual(results, [])

    @responses.activate
    def test_ns_records(self):
        responses.get(
            url="https://dns.google.com/resolve",
            match=[
                responses.matchers.query_param_matcher(
                    {"name": "example.com", "type": "NS"}
                )
            ],
            json={
                "Answer": [
                    {
                        "name": "example.com.",
                        "type": 2,
                        "TTL": 16028,
                        "data": "a.iana-servers.net.",
                    },
                    {
                        "name": "example.com.",
                        "type": 2,
                        "TTL": 16028,
                        "data": "b.iana-servers.net.",
                    },
                ]
            },
        )
        results = self.client.ns("example.com")
        self.assertEqual(results, ["a.iana-servers.net", "b.iana-servers.net"])

    @responses.activate
    def test_a_records(self):
        responses.get(
            url="https://dns.google.com/resolve",
            match=[
                responses.matchers.query_param_matcher(
                    {"name": "example.com", "type": "A"}
                )
            ],
            json={
                "Answer": [
                    {
                        "name": "example.com.",
                        "type": 1,
                        "TTL": 21267,
                        "data": "93.184.216.34",
                    }
                ]
            },
        )
        results = self.client.a("example.com")
        self.assertEqual(results, ["93.184.216.34"])

    @responses.activate
    def test_cname_records(self):
        responses.get(
            url="https://dns.google.com/resolve",
            match=[
                responses.matchers.query_param_matcher(
                    {"name": "blog.google.com", "type": "CNAME"}
                )
            ],
            json={
                "Answer": [
                    {
                        "name": "blog.google.com.",
                        "type": 5,
                        "TTL": 138,
                        "data": "www.blogger.com.",
                    }
                ]
            },
        )
        results = self.client.cname("blog.google.com")
        self.assertTrue("www.blogger.com" in results)

    @responses.activate
    def test_mx_records(self):
        responses.get(
            url="https://dns.google.com/resolve",
            match=[
                responses.matchers.query_param_matcher(
                    {"name": "google.com", "type": "MX"}
                )
            ],
            json={
                "Answer": [
                    {
                        "name": "google.com.",
                        "type": 15,
                        "TTL": 219,
                        "data": "10 smtp.google.com.",
                    }
                ]
            },
        )
        results = self.client.mx("google.com")
        self.assertEqual(results, ["smtp.google.com"])

    @responses.activate
    def test_txt_records(self):
        responses.get(
            url="https://dns.google.com/resolve",
            match=[
                responses.matchers.query_param_matcher(
                    {"name": "google.com", "type": "TXT"}
                )
            ],
            json={
                "Answer": [
                    {
                        "name": "google.com.",
                        "type": 16,
                        "TTL": 2498,
                        "data": "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ",
                    },
                    {
                        "name": "google.com.",
                        "type": 16,
                        "TTL": 2498,
                        "data": "v=spf1 include:_spf.google.com ~all",
                    },
                ]
            },
        )
        results = self.client.txt("google.com")
        self.assertTrue("v=spf1 include:_spf.google.com ~all" in results)
