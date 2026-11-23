"""Unit tests for the pure helpers (no HTTP, no STIX)."""

import pytest
from connector.utils import SochainUtils, detect_network, explorer_url


@pytest.mark.parametrize(
    "address, network",
    [
        ("bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9cetdj", "BTC"),
        ("BC1QXHMDUFSVNUAAAER4YNZ88FSPDSXQ2H9E9CETDJ", "BTC"),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "BTC"),
        ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "BTC"),
        ("ltc1qg82tdq4a0r8ulfsr3hvhulmq3pwjl3h6v6k3xv", "LTC"),
        ("LQTpS3VaYTjCr4s9Y1t5zbeY26zevf7Fb3", "LTC"),
        ("MQd1fJwqBJvwLuyhr17PhEFx1swiqDbPQS", "LTC"),
        ("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L", "DOGE"),
        ("A9Ud4YjbBbtbH9HHqjVJRUXxfV1bCZ6Rq9", "DOGE"),
        ("t1Rv4exT7bqhZqi2j7xz8bUHDMxwosrjADU", "ZEC"),
        ("t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd", "ZEC"),
    ],
)
def test_detect_network(address, network):
    assert detect_network(address) == network


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "bc1QxhmdufsvnuaaaEr4ynz88fspdsxq2h9e9cetdj",
        "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7Div0Na",
        "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly",
    ],
)
def test_detect_network_rejects_other_values(value):
    assert detect_network(value) is None


def test_explorer_url():
    assert (
        explorer_url("DOGE", "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L")
        == "https://sochain.com/doge/address/DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"
    )


def test_build_description():
    description = SochainUtils.build_description(
        "BTC",
        {
            "txs_sent": 1796,
            "txs_received": 32014,
            "txs_total": 32014,
            "confirmed_balance": "0.12771030",
            "unconfirmed_balance": "0.00000000",
            "confirmed_received": "285785.38685032",
            "first_active": {"height": 687848, "time": 1623874601},
            "last_active": {"height": 972455, "time": 1792576976},
        },
    )

    assert "**SoChain (Bitcoin)**" in description
    assert "- Balance: 0.12771030 BTC (unconfirmed: 0.00000000 BTC)" in description
    assert "- Received in total: 285785.38685032 BTC" in description
    assert "- Transactions: 32,014 (1,796 sending, 32,014 receiving)" in description
    assert "- First active: block 687,848, 2021-06-16 20:16 UTC" in description
    assert "- Last active: block 972,455" in description


def test_build_description_for_an_unused_address():
    description = SochainUtils.build_description(
        "LTC",
        {
            "txs_sent": 0,
            "txs_received": 0,
            "txs_total": 0,
            "confirmed_balance": "0.00000000",
            "unconfirmed_balance": "0.00000000",
            "confirmed_received": "0.00000000",
            "first_active": None,
            "last_active": None,
        },
    )

    assert "**SoChain (Litecoin)**" in description
    assert "- No transactions yet" in description


def test_build_poisoning_note_lists_full_addresses():
    finding = {
        "dust_txid": "a" * 64,
        "amount": "0.00000546",
        "sender": "bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9ceaaaa",
        "imitates": "bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9cebbbb",
        "height": None,
        "confirmed": False,
    }
    note = SochainUtils.build_poisoning_note(
        "BTC", "bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9cetdj", [finding]
    )

    assert note.startswith("SoChain found 1 look-alike address that sent")
    assert "| bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9ceaaaa |" in note
    assert "| bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9cebbbb |" in note
    assert "| 0.00000546 BTC | unconfirmed |" in note


def test_poisoning_findings_ignores_bad_shapes():
    assert SochainUtils.poisoning_findings({}) == []
    assert SochainUtils.poisoning_findings(None) == []
    assert SochainUtils.poisoning_findings({"findings": [{"a": 1}, "x"]}) == [{"a": 1}]
