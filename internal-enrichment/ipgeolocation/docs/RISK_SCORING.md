# Risk Scoring Algorithm

## Overview

The connector normalizes heterogeneous risk signals from IPGeolocation.io into
a single unified score (0–100) and human-readable risk level.

## Algorithm

### Step 1: Base Score

Start with the `threat_score` from the IPGeolocation.io Security API (0–100).

### Step 2: Additive Modifiers

Apply bonuses for each active boolean threat flag:

| Flag                   | Weight | Rationale                                    |
|------------------------|--------|----------------------------------------------|
| `is_tor`               | +15    | Strong anonymization, common in attacks       |
| `is_known_attacker`    | +15    | Direct threat intelligence signal             |
| `is_spam`              | +10    | Active abuse source                           |
| `is_bot`               | +10    | Automated malicious activity                  |
| `is_residential_proxy` | +8     | Hard-to-detect anonymization                  |
| `is_vpn`               | +5     | Anonymization (commercial VPNs common)        |
| `is_proxy`             | +5     | Anonymization (datacenter proxies)            |
| `is_relay`             | +3     | Mild anonymization (Apple Relay, etc.)        |
| `is_anonymous`         | +3     | Only if not already captured by above flags   |
| `is_cloud_provider`    | +2     | Infrastructure signal, not inherently bad     |

### Step 3: Cap at 100

`unified_score = min(base + sum(bonuses), 100)`

### Step 4: Risk Level

| Score Range | Risk Level |
|-------------|------------|
| 0–20        | Low        |
| 21–50       | Medium     |
| 51–80       | High       |
| 81–100      | Critical   |

### Step 5: Confidence

Derived from API-provided confidence scores:

- Collect `vpn_confidence_score`, `proxy_confidence_score`, and
  `min(threat_score + 20, 100)`
- Average available scores
- Default to 70 if no confidence data is available

## Examples

### Clean DNS Resolver (8.8.8.8)
- Base threat_score: 0
- Flags: `is_cloud_provider=true` (+2)
- Unified: 2 → **Low Risk**

### VPN + Known Attacker (2.56.188.34)
- Base threat_score: 80
- Flags: `is_vpn` (+5), `is_proxy` (+5), `is_residential_proxy` (+8),
  `is_known_attacker` (+15), `is_cloud_provider` (+2)
- Raw: 80 + 35 = 115, capped to 100 → **Critical Risk**

### Simple VPN User
- Base threat_score: 20
- Flags: `is_vpn` (+5)
- Unified: 25 → **Medium Risk**

## Design Decisions

1. **Additive model**: Bonuses compound because multiple threat signals
   simultaneously present a higher risk than any single signal.
2. **TOR/attacker weighted highest**: These are the strongest indicators of
   malicious intent.
3. **Cloud provider weighted low**: Many legitimate services run on cloud
   infrastructure.
4. **Deduplication of anonymous**: `is_anonymous` is only counted when it is
   not already implied by VPN, proxy, TOR, or relay flags.
5. **Explanation always generated**: Analysts see *why* the score is what it
   is, not just a number.
