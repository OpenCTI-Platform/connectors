"""
Check the connector against the real DNSlytics services while spending as few credits as possible.
It reuses the connector's own client and hosting code, without OpenCTI.

Free (0 credits):
    python tools/live_check.py
        DNS + IP2ASN for armeniadaily.am (or --domains a.am,b.am): checks the provider
        name that the `provider:` label will get.
    DNSLYTICS_API_KEY=... python tools/live_check.py
        Same, plus AccountInfo: checks the key and prints the credit balance.
    python tools/live_check.py --from-recording rec.json --sample 100 --csv sample.csv
        DNS + IP2ASN for up to 100 active domains of a recorded search, written to a CSV
        with the DNSlytics web URL of each domain, for the kill-line comparison by hand.

Paid (10 credits, only with --spend-one-call):
    DNSLYTICS_API_KEY=... python tools/live_check.py --spend-one-call --record rec.json
        One `v2/dataset/domains` call with --query (default: the RFC query). Reads the balance
        before and after (free) to show the real cost, and saves the answer so the tests,
        the mock server and --from-recording can replay it for free.
"""

import argparse
import csv
import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from connector.hosting import derive_hosting  # noqa: E402
from dnslytics_client import DnslyticsClient  # noqa: E402

RFC_QUERY = "(name:*daily* OR name:*news*) AND (name:*armenia*)"


class _Logger:
    """Mimics `helper.connector_logger`."""

    def __init__(self):
        logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
        self._log = logging.getLogger("dnslytics")

    def _emit(self, level, message, meta=None):
        self._log.log(level, "%s %s", message, meta or "")

    def debug(self, message, meta=None):
        self._emit(logging.DEBUG, message, meta)

    def info(self, message, meta=None):
        self._emit(logging.INFO, message, meta)

    def warning(self, message, meta=None):
        self._emit(logging.WARNING, message, meta)

    def error(self, message, meta=None):
        self._emit(logging.ERROR, message, meta)


class _Helper:
    connector_logger = _Logger()


def check_hosting(client: DnslyticsClient, domains: list[str]) -> list[dict]:
    hosting = derive_hosting(domains, client)
    rows = []
    for domain in domains:
        ips = hosting.ips_by_domain.get(domain, [])
        ases = [hosting.as_by_ip.get(ip) for ip in ips]
        rows.append(
            {
                "domain": domain,
                "ips": " ".join(ips),
                "asn": " ".join(sorted({str(a.number) for a in ases if a})),
                "provider": " | ".join(sorted({a.name for a in ases if a and a.name})),
                "dnslytics_url": f"https://search.dnslytics.com/domain/{domain}",
            }
        )
    for ip, error in hosting.ip2asn_errors.items():
        print(f"IP2ASN error for {ip}: {error}")
    print(f"IP2ASN calls: {hosting.ip2asn_calls} (free, 2,500/day)")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--domains",
        default="armeniadaily.am",
        help="Comma-separated domains for the free hosting check",
    )
    parser.add_argument(
        "--from-recording",
        type=Path,
        help="Recorded search answer (JSON) to sample domains from",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=100,
        help="Max active domains taken from --from-recording",
    )
    parser.add_argument(
        "--csv", type=Path, help="Write the hosting rows to this CSV file"
    )
    parser.add_argument(
        "--spend-one-call",
        action="store_true",
        help="Make ONE paid dataset/domains call (10 credits)",
    )
    parser.add_argument("--query", default=RFC_QUERY)
    parser.add_argument(
        "--record", type=Path, help="Where to save the paid call's answer"
    )
    parser.add_argument(
        "--api-base-url",
        default=os.environ.get("DNSLYTICS_API_BASE_URL", "https://api.dnslytics.net"),
    )
    args = parser.parse_args()

    api_key = os.environ.get("DNSLYTICS_API_KEY", "")
    client = DnslyticsClient(_Helper(), api_base_url=args.api_base_url, api_key=api_key)

    if api_key:
        info = client.account_info()
        print(
            f"AccountInfo (free): {info.get('apicredits')} credits left, {info.get('apicalls')}/{info.get('apilimits')} calls today"
        )
    elif args.spend_one_call:
        print("--spend-one-call needs DNSLYTICS_API_KEY")
        return 2

    if args.spend_one_call:
        before = client.account_info().get("apicredits")
        result = client.search_domains(args.query, page=1)
        after = client.account_info().get("apicredits")
        print(f"Query: {args.query}")
        print(
            f"ndomains={result.ndomains}, returned={len(result.domains)}, "
            f"active={sum(hit.active for hit in result.domains)}"
        )
        if isinstance(before, int) and isinstance(after, int):
            print(f"Credits spent: {before - after} (expected 10)")
        if args.record:
            recording = {
                "status": "succeed",
                "data": {
                    "question": {"query": args.query, "page": 1},
                    "typeinfo": "dataset/domains",
                    "ndomains": result.ndomains,
                    "domains": [
                        {"domain": h.domain, "active": h.active} for h in result.domains
                    ],
                },
            }
            args.record.write_text(json.dumps(recording, indent=2), encoding="utf-8")
            print(
                f"Saved to {args.record}: replay it with tools/mock_dnslytics_server.py --dataset {args.record}"
            )
        return 0

    if args.from_recording:
        data = json.loads(args.from_recording.read_text(encoding="utf-8"))["data"]
        domains = [d["domain"] for d in data["domains"] if d.get("active")][
            : args.sample
        ]
    else:
        domains = [d.strip() for d in args.domains.split(",") if d.strip()]

    rows = check_hosting(client, domains)
    for row in rows:
        print(
            f"{row['domain']}: {row['ips'] or '(does not resolve)'} -> AS{row['asn'] or '?'} "
            f"provider:{row['provider'] or '?'}"
        )
    if args.csv:
        with args.csv.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=list(rows[0]) if rows else ["domain"]
            )
            writer.writeheader()
            writer.writerows(rows)
        print(f"Wrote {len(rows)} rows to {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
