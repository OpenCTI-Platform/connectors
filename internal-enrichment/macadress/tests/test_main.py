"""Unit tests for the pure result-shaping helpers (MacadressUtils)."""

from connector.utils import MacadressUtils

APPLE = {
    "mac": "F0:18:98:11:22:33",
    "valid": True,
    "organization": "Apple, Inc.",
    "country": "US",
    "block_type": "MA-L",
    "matched_prefix": "F0:18:98",
    "registered": True,
    "locally_administered": False,
    "potentially_randomized": False,
    "randomization_confidence": "none",
    "vendor_lookup_reliable": True,
    "explanation": "Universally administered unicast address registered to Apple, Inc.",
    "device": {"category": "smartphone", "confidence": "medium"},
    "virtualization": {"detected": False, "platform": None},
    "special_use": {"detected": False, "type": None},
    "local_vendor_derivation": {"detected": False},
    "vendor": {"lookup_url": "https://macadress.com/vendor/apple-inc"},
}

VMWARE = {
    "mac": "00:50:56:AA:BB:CC",
    "valid": True,
    "organization": "VMware, Inc.",
    "country": "US",
    "registered": True,
    "locally_administered": False,
    "potentially_randomized": False,
    "vendor_lookup_reliable": True,
    "device": {"category": "virtual_machine"},
    "virtualization": {"detected": True, "platform": "VMware"},
    "special_use": {"detected": False},
    "vendor": None,
}

RANDOM = {
    "mac": "F2:11:22:33:44:55",
    "valid": True,
    "organization": None,
    "registered": False,
    "locally_administered": True,
    "potentially_randomized": True,
    "randomization_confidence": "likely",
    "vendor_lookup_reliable": False,
    "explanation": "Locally administered; low 40 bits look random.",
    "device": {"category": "unknown"},
    "virtualization": {"detected": False},
    "special_use": {"detected": False},
    "vendor": None,
}


def test_labels_for_registered_vendor():
    labels = MacadressUtils.build_labels(APPLE)
    assert "macadress" in labels
    assert "smartphone" in labels
    assert "universally-administered" in labels
    assert "mac-randomized" not in labels


def test_labels_for_virtual_and_random():
    assert "virtualization:vmware" in MacadressUtils.build_labels(VMWARE)
    random_labels = MacadressUtils.build_labels(RANDOM)
    assert "locally-administered" in random_labels
    assert "mac-randomized" in random_labels
    # An "unknown" device category is not emitted as a label.
    assert "unknown" not in random_labels


def test_external_references_include_lookup_and_vendor():
    refs = MacadressUtils.build_external_references(APPLE, "F0:18:98:11:22:33")
    urls = [ref["url"] for ref in refs]
    assert "https://macadress.com/lookup/F0:18:98:11:22:33" in urls
    assert "https://macadress.com/vendor/apple-inc" in urls
    # No vendor lookup_url -> only the analysis link.
    assert (
        len(MacadressUtils.build_external_references(VMWARE, "00:50:56:AA:BB:CC")) == 1
    )


def test_description_and_summary_mention_vendor():
    description = MacadressUtils.build_description(APPLE)
    assert "**Vendor:** Apple, Inc. (US)" in description
    assert "`F0:18:98`" in description
    summary = MacadressUtils.build_summary("F0:18:98:11:22:33", APPLE)
    assert summary.startswith("## macadress.com Results")
    assert "Apple, Inc." in summary


def test_description_handles_locally_administered():
    assert "locally administered" in MacadressUtils.build_description(RANDOM)
