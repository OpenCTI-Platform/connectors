from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ObservableIocFlags:
    file: bool = False
    domain: bool = False
    url: bool = False
    ip: bool = False
    yara: bool = False
    suricata: bool = False
    email: bool = False


_IOC_INDICATOR_PRESET = ObservableIocFlags(file=True, domain=True, url=True, ip=True)
_NETWORK_NON_IOC_PRESET = ObservableIocFlags(domain=False, url=False, ip=False)


IOC_OBSERVABLE_FLAGS: Mapping[str, ObservableIocFlags] = {
    "apt/threat": _IOC_INDICATOR_PRESET,
    "hi/threat": _IOC_INDICATOR_PRESET,
    "apt/threat_actor": _IOC_INDICATOR_PRESET,
    "hi/threat_actor": _IOC_INDICATOR_PRESET,
    "malware/malware": _IOC_INDICATOR_PRESET,
    "malware/signature": ObservableIocFlags(yara=True, suricata=True),
    "malware/yara": ObservableIocFlags(yara=True, suricata=True),
    "suspicious_ip/open_proxy": _NETWORK_NON_IOC_PRESET,
    "suspicious_ip/scanner": _NETWORK_NON_IOC_PRESET,
    "suspicious_ip/socks_proxy": _NETWORK_NON_IOC_PRESET,
    "suspicious_ip/tor_node": _NETWORK_NON_IOC_PRESET,
    "suspicious_ip/vpn": _NETWORK_NON_IOC_PRESET,
}


def get_observable_ioc_flags(collection: str) -> ObservableIocFlags:
    return IOC_OBSERVABLE_FLAGS.get(collection, ObservableIocFlags())


@dataclass(frozen=True)
class SpecialCollection:
    method_name: str
    is_ioc: bool
    tlp_strict: str | None = None
    tlp_fallback: str | None = None


SPECIAL_COLLECTIONS: Mapping[str, SpecialCollection] = {
    "compromised/account_group": SpecialCollection(
        "generate_compromised_account_group", is_ioc=False, tlp_strict="red"
    ),
    "osi/public_leak": SpecialCollection(
        "generate_osi_public_leak", is_ioc=False, tlp_fallback="amber"
    ),
    "osi/git_repository": SpecialCollection(
        "generate_osi_git_repository", is_ioc=False, tlp_fallback="amber"
    ),
    "compromised/access": SpecialCollection(
        "generate_compromised_access", is_ioc=False, tlp_fallback="amber"
    ),
    "compromised/bank_card_group": SpecialCollection(
        "generate_compromised_bank_card_group",
        is_ioc=False,
        tlp_fallback="red",
    ),
    "compromised/spd": SpecialCollection(
        "generate_compromised_spd", is_ioc=False, tlp_fallback="amber"
    ),
    "compromised/masked_card": SpecialCollection(
        "generate_compromised_masked_card", is_ioc=False, tlp_fallback="red"
    ),
    "compromised/discord": SpecialCollection(
        "generate_compromised_discord", is_ioc=False, tlp_fallback="red"
    ),
    "compromised/messenger": SpecialCollection(
        "generate_compromised_messenger", is_ioc=False, tlp_fallback="red"
    ),
    "malware/cnc": SpecialCollection(
        "generate_malware_cnc", is_ioc=True, tlp_fallback="amber"
    ),
    "malware/config": SpecialCollection("generate_malware_config", is_ioc=False),
    "ioc/primary": SpecialCollection(
        "generate_ioc_primary", is_ioc=True, tlp_strict="amber"
    ),
    "hi/open_threats": SpecialCollection(
        "generate_hi_open_threats", is_ioc=False, tlp_fallback="amber"
    ),
    "osi/vulnerability": SpecialCollection(
        "generate_osi_vulnerability", is_ioc=False, tlp_fallback="amber"
    ),
    "attacks/ddos": SpecialCollection(
        "generate_attacks_ddos", is_ioc=False, tlp_fallback="amber"
    ),
    "darkweb/forums": SpecialCollection(
        "generate_darkweb_forums", is_ioc=False, tlp_fallback="amber"
    ),
    "attacks/deface": SpecialCollection(
        "generate_attacks_deface", is_ioc=False, tlp_fallback="amber"
    ),
    "attacks/phishing_group": SpecialCollection(
        "generate_attacks_phishing_group", is_ioc=True, tlp_fallback="amber"
    ),
    "attacks/phishing_kit": SpecialCollection(
        "generate_attacks_phishing_kit", is_ioc=True, tlp_fallback="amber"
    ),
}


def resolve_special_tlp(spec: SpecialCollection, event_tlp: str | None) -> str | None:
    if spec.tlp_strict is not None:
        return spec.tlp_strict
    if spec.tlp_fallback is not None:
        return event_tlp or spec.tlp_fallback
    return event_tlp
