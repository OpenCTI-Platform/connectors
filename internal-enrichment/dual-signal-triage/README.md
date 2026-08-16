# Dual Signal Triage (OpenCTI Internal Enrichment)

Playbook-compatible enrichment that applies **Gate→Prove** dual-signal triage labels to OpenCTI cases and detections.

## Hard rule

**Machine-learning confidence ≠ signature true positive.**

| Signal basis | Disposition | Labels (examples) |
|---|---|---|
| `ml_only` | escalate | `dual-signal:ml-only`, `gate:escalate`, `remediation:deny-auto-contain` |
| `signature` | gated_fix_now | `dual-signal:signature`, `gate:fix-now`, `remediation:hitl-required` |
| `corroborated` | gated_fix_now | `dual-signal:corroborated`, `gate:fix-now`, `remediation:hitl-required` |
| `unknown` | accept | `dual-signal:unknown`, `gate:accept` |

## What it looks for

Entity name/description/labels/custom fields containing markers such as:

- OCSF-aligned: `is_ml_only`, `is_corroborated`
- Snort-family: `gid:411`, `SnortML`
- Signature classifications / dual-signal corroboration phrases

## Scope

Default: `Case-Incident,Incident,Report,Indicator`

## Configuration

See `src/config.yml.sample` and `docker-compose.yml`.

| Variable | Default | Meaning |
|---|---|---|
| `DUAL_SIGNAL_TRIAGE_MAX_TLP_LEVEL` | `amber+strict` | Max TLP allowed for enrichment |
| `DUAL_SIGNAL_TRIAGE_CREATE_NOTE` | `true` | Attach a Note with triage summary |

## Playbooks

Wire this connector after alert/case creation. Automations that call containment tools should **deny** when `remediation:deny-auto-contain` is present, and require Gate→Prove HITL when `remediation:hitl-required` is present.

## Portable sisters

- OCSF: https://github.com/ocsf/ocsf-schema/pull/1732
- Sigma: https://github.com/SigmaHQ/sigma/pull/6237
- Elastic: https://github.com/elastic/detection-rules/pull/6662
- Splunk: https://github.com/splunk/security_content/issues/4220

## Production consumer

Aegis Decision Fabric (gated remediation): https://github.com/AAH20/aegis-decision-fabric  
Paid Continuous Trust / consultation: https://a2zsoc.com/consultation
