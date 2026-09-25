"""
Local stand-in for the DNSlytics premium API, for end-to-end tests that must not spend credits.

It answers:
- GET /v2/dataset/domains  with the JSON file given by --dataset (a fixture or a recording
  made by `live_check.py --spend-one-call`), whatever the query
- GET /v1/accountinfo       with a fixed balance

IP2ASN and DNS stay real: both are free.

Usage:
    python tools/mock_dnslytics_server.py --dataset tests/fixtures/dataset_domains_rfc_query.json
then deploy the connector with DNSLYTICS_API_BASE_URL=http://<this host>:8000
(from a container on Docker Desktop: http://host.docker.internal:8000).
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ACCOUNT_INFO = {
    "status": "succeed",
    "data": {
        "typeinfo": "accountinfo",
        "apicredits": 1000,
        "apilimits": 20000,
        "apicalls": 0,
    },
}


def make_handler(dataset: dict):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: dict) -> None:
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):  # noqa: N802 (http.server naming)
            url = urlparse(self.path)
            params = parse_qs(url.query)
            if not params.get("apikey"):
                return self._send(
                    403, {"status": "error", "data": "Forbidden access denied!"}
                )
            if url.path == "/v2/dataset/domains":
                body = json.loads(json.dumps(dataset))
                body.setdefault("data", {})["question"] = {
                    "query": params.get("q", [""])[0],
                    "page": int(params.get("page", ["1"])[0]),
                }
                return self._send(200, body)
            if url.path == "/v1/accountinfo":
                return self._send(200, ACCOUNT_INFO)
            return self._send(404, {"status": "error", "data": "Not found"})

        def log_message(self, fmt, *args):
            # Never print the API key that sits in the query string
            print(
                f"{self.command} {urlparse(self.path).path} -> {args[1] if len(args) > 1 else ''}"
            )

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
        help="JSON body served for /v2/dataset/domains",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    server = ThreadingHTTPServer((args.host, args.port), make_handler(dataset))
    print(
        f"Mock DNSlytics API on http://{args.host}:{args.port}, serving {args.dataset}"
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
