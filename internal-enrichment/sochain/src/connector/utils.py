"""Pure helpers: tell which network an address is on, and shape SoChain answers
into an observable description, labels, external references and note text.
No HTTP, no STIX, no config access."""

import re
from datetime import datetime, timezone

NETWORK_NAMES = {
    "BTC": "Bitcoin",
    "LTC": "Litecoin",
    "DOGE": "Dogecoin",
    "ZEC": "Zcash",
}

_BASE58 = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{26,35}$")
_BECH32 = re.compile(r"^(bc|ltc)1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,87}$")
_BECH32_NETWORKS = {"bc": "BTC", "ltc": "LTC"}
# First character of a Base58 address and the network it belongs to.
# "3" is also an old Litecoin P2SH prefix; the same address is valid on both,
# and Bitcoin is far more common.
_BASE58_PREFIXES = {
    "1": "BTC",
    "3": "BTC",
    "L": "LTC",
    "M": "LTC",
    "D": "DOGE",
    "A": "DOGE",
    "9": "DOGE",
}


def detect_network(address: str) -> str | None:
    """Return the SoChain network code of a mainnet address, or None.

    Covers Bitcoin, Litecoin, Dogecoin and Zcash transparent addresses. The
    checksum is not verified here: SoChain answers 404 for an invalid address.
    """
    value = (address or "").strip()
    if not value:
        return None

    # Bech32 is all lowercase or all uppercase, never mixed.
    if value == value.lower() or value == value.upper():
        match = _BECH32.match(value.lower())
        if match:
            return _BECH32_NETWORKS[match.group(1)]

    if not _BASE58.match(value):
        return None
    if value[:2] in ("t1", "t3") and len(value) == 35:
        return "ZEC"
    return _BASE58_PREFIXES.get(value[0])


def explorer_url(network: str, address: str) -> str:
    return f"https://sochain.com/{network.lower()}/address/{address}"


def _count(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "unknown"


def _block(activity) -> str | None:
    if not isinstance(activity, dict):
        return None
    height = activity.get("height")
    stamp = activity.get("time")
    parts = []
    if height is not None:
        parts.append(f"block {_count(height)}")
    if stamp is not None:
        try:
            moment = datetime.fromtimestamp(int(stamp), tz=timezone.utc)
            parts.append(moment.strftime("%Y-%m-%d %H:%M UTC"))
        except (TypeError, ValueError, OverflowError, OSError):
            pass
    return ", ".join(parts) or None


class SochainUtils:
    @staticmethod
    def build_description(network: str, summary: dict) -> str:
        """Markdown description of the wallet from /address_summary."""
        unit = network
        lines = [f"**SoChain ({NETWORK_NAMES.get(network, network)})**", ""]
        lines.append(
            f"- Balance: {summary.get('confirmed_balance', 'unknown')} {unit}"
            f" (unconfirmed: {summary.get('unconfirmed_balance', 'unknown')} {unit})"
        )
        lines.append(
            f"- Received in total: {summary.get('confirmed_received', 'unknown')} {unit}"
        )
        lines.append(
            f"- Transactions: {_count(summary.get('txs_total'))}"
            f" ({_count(summary.get('txs_sent'))} sending,"
            f" {_count(summary.get('txs_received'))} receiving)"
        )
        first = _block(summary.get("first_active"))
        last = _block(summary.get("last_active"))
        if first:
            lines.append(f"- First active: {first}")
        if last:
            lines.append(f"- Last active: {last}")
        if not first and not last:
            lines.append("- No transactions yet")
        return "\n".join(lines)

    @staticmethod
    def build_external_reference(network: str, address: str) -> dict:
        return {
            "source_name": "SoChain",
            "url": explorer_url(network, address),
            "description": f"{NETWORK_NAMES.get(network, network)} address on SoChain",
        }

    @staticmethod
    def poisoning_findings(poisoning: dict) -> list[dict]:
        findings = poisoning.get("findings") if isinstance(poisoning, dict) else None
        return [f for f in findings or [] if isinstance(f, dict)]

    @staticmethod
    def build_poisoning_note(network: str, address: str, findings: list[dict]) -> str:
        """Markdown note listing the look-alike addresses, in full."""
        lines = [
            f"SoChain found {len(findings)} look-alike address"
            f"{'' if len(findings) == 1 else 'es'} that sent {address} dust, "
            "imitating addresses it paid or was paid by. Copying a look-alike "
            "from this address's history pays the scammer.",
            "",
            "| Look-alike (sender) | Imitates | Dust transaction | Dust amount | Block |",
            "|---|---|---|---|---|",
        ]
        for finding in findings:
            height = finding.get("height")
            block = _count(height) if height is not None else "unconfirmed"
            lines.append(
                f"| {finding.get('sender', '')} | {finding.get('imitates', '')} "
                f"| {finding.get('dust_txid', '')} "
                f"| {finding.get('amount', '')} {network} | {block} |"
            )
        lines.append("")
        lines.append(f"Source: {explorer_url(network, address)}")
        return "\n".join(lines)
