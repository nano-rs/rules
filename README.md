# nano Detection Rules

Official detection rule repository for [nano](https://nano.rs). These rules are written in native nPL (nano Pipe Language) format and can be synced directly into your nano deployment.

## Usage

Add this repository in nano:

1. Navigate to **Settings → Rule Repositories**
2. Click **Add Repository**
3. Enter:
   - **URL**: `https://github.com/nano-rs/rules`
   - **Branch**: `main`
   - **Format**: nano (nPL)
4. Click **Sync** to fetch rules
5. Browse and import rules as needed

## Repository Structure

```
├── credential_access/    # Credential theft, brute force, dumping
├── initial_access/       # Phishing, exploitation, valid accounts
├── lateral_movement/     # Remote services, pass-the-hash
├── execution/            # Script execution, command-line abuse
├── defense_evasion/      # Obfuscation, indicator removal
├── exfiltration/         # Data theft, staging, transfer
├── persistence/          # Scheduled tasks, registry, services
├── discovery/            # Network/system enumeration
└── command_control/      # C2 communications, beaconing
```

## Rule Format

Rules use YAML frontmatter with nPL queries:

```yaml
---
title: rule_name
description: What this rule detects
author: author-name
severity: critical|high|medium|low|informational
mode: staging
mitre_tactics: TA0006
mitre_techniques: T1110.001
tags:
  - tag1
  - tag2
---
source_type="logs"
| where condition="value"
| stats count() by field
| where count > threshold
```

## Advanced Features

These rules showcase nano's advanced detection capabilities:

### Sequence Detection
Detect ordered event chains (e.g., failed logins → success):
```
| sequence by user maxspan=5m [status="failure"] [status="success"]
```

### Prevalence Filtering
Alert only on rare/new artifacts:
```
| prevalence enrich=true window=30d
| where hash_prevalence < 5 AND hash_first_seen > now() - INTERVAL 24 HOUR
```

### Risk-Based Scoring
Dynamic risk calculation based on context:
```
| risk score=if(external_ip, 80, 40) entity=user factor="Login source"
```

## Contributing

1. Fork this repository
2. Create rules following the format above
3. Test in staging mode before submitting
4. Submit a pull request

## License

Detection Rule License (DRL) - See [LICENSE](LICENSE)

Rules may be used freely for detection purposes. Attribution required for redistribution.
