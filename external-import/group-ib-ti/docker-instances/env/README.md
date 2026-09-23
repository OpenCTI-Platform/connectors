# Environment layout

The `docker-instances/` layout runs one image per profile. Each profile is a separate connector registration in OpenCTI (own `CONNECTOR_ID`) and consumes a chosen subset of Group-IB TI collections.

For the full **collection → OpenCTI entity / relationship / TLP** mapping see the *Collection → OpenCTI mapping* section in [`../../README.md`](../../README.md).

## Layout

1. **`common.env`** — shared template, generated from the minimal multi-instance template in this folder (globals only — OpenCTI, MQ, TI API, extra settings; per-collection knobs live in the per-profile group files):

   ```bash
   cd docker-instances/env
   cp common.env.sample common.env
   ```

   Then edit `env/common.env`: fill in `OPENCTI_TOKEN`, `TI_API__USERNAME`, `TI_API__TOKEN`. Tweak global settings as needed.

2. **`env/groups/<profile>.env`** — copy from the matching `<profile>.env.sample` in `env/groups/`, set a unique `CONNECTOR_ID` (registered in OpenCTI), adjust `CONNECTOR_NAME` / `CONNECTOR_DOCKER_CONTAINER_NAME` as needed. Per-collection overrides (TTL, DEFAULT_DATE, INCLUDE_* labels, …) also belong in this file.

3. **Load order** (in `docker-compose.yml`): `common.env` first, then `env/groups/<profile>.env`. Later file wins on duplicate keys.

## Profiles (16 total)

| Profile | Compose service | Collections (TI API) | TLP fallback |
|---------|-----------------|----------------------|--------------|
| **accounts-unique** | `connector_accounts_unique` | `compromised/account_group` (UNIQUE=1) | red (strict) |
| **accounts-combolist** | `connector_accounts_combolist` | `compromised/account_group` (COMBOLIST=1) | red (strict) |
| **cards** | `connector_cards` | `compromised/bank_card_group`, `compromised/masked_card` | red |
| **leaks** | `connector_leaks` | `osi/public_leak`, `osi/git_repository` | amber |
| **compromised-access** | `connector_compromised_access` | `compromised/access` | amber |
| **compromised-chat** | `connector_compromised_chat` | `compromised/discord`, `compromised/messenger` | red |
| **vulnerabilities** | `connector_vulnerabilities` | `osi/vulnerability` | per evaluation |
| **spd** | `connector_spd` | `compromised/spd` | amber |
| **suspicious-ip** | `connector_suspicious_ip` | `suspicious_ip/{open_proxy,scanner,socks_proxy,tor_node,vpn}` | per evaluation |
| **malware-cnc** | `connector_malware_cnc` | `malware/cnc` | amber |
| **attacks** | `connector_attacks` | `attacks/{ddos,deface,phishing_group,phishing_kit}` | per evaluation |
| **darkweb** | `connector_darkweb` | `darkweb/forums` | amber |
| **apt-reports** | `connector_apt_reports` | `apt/threat`, `apt/threat_actor` | amber+strict (actors) |
| **hi-reports** | `connector_hi_reports` | `hi/threat`, `hi/threat_actor`, `hi/open_threats` | amber+strict / amber (open_threats) |
| **malware-reports** | `connector_malware_reports` | `malware/malware`, `malware/config`, `malware/signature`, `malware/yara` | per evaluation |
| **iocs** | `connector_iocs` | `ioc/primary` | amber (strict) |
