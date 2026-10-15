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

nano registers this repository on `main` automatically, so most deployments
never need to add it by hand.

## Branches

| Branch | Content | Intended deployment |
|---|---|---|
| `main` | **OCSF 1.9** rules | nano (the Iceberg/chDB OCSF lake) |
| `legacy/clickhouse` | Archive: the UDM rule sets plus the older OCSF rule sets | The retired ClickHouse edition |
| `ocsf-1.9` | Frozen copy of the OCSF 1.9 rules | Kept for installs that still pin it; it receives no new rules, use `main` |

Legacy ClickHouse-edition users should point their rule repository at
`legacy/clickhouse` or migrate to the OCSF lake. That branch is an archive for
anyone who wants to go back and maintain their own rules; it is not updated.

## Repository Structure

```
├── collection-ocsf/             # Data collection, staging, capture
├── command_control-ocsf/        # C2 communications, beaconing
├── credential_access-ocsf/      # Credential theft, brute force, dumping
├── defense_evasion-ocsf/        # Obfuscation, indicator removal
├── discovery-ocsf/              # Network/system enumeration
├── execution-ocsf/              # Script execution, command-line abuse
├── exfiltration-ocsf/           # Data theft, staging, transfer
├── impact-ocsf/                 # Ransomware, wipers, destruction, hijacking
├── initial_access-ocsf/         # Phishing, exploitation, valid accounts
├── lateral_movement-ocsf/       # Remote services, pass-the-hash
├── persistence-ocsf/            # Scheduled tasks, registry, services
├── privilege_escalation-ocsf/   # Token abuse, UAC bypass, escalation
└── demo-ocsf/                   # Curated demo rules
```

The `-ocsf` suffix on every top-level folder is load-bearing: nano resolves a
rule folder by its first path segment plus `-ocsf` (`impact` → `impact-ocsf`).
A nested `ocsf/` tree, a version-suffixed folder such as `impact-ocsf-1.9/`, or
any other shape will never be found and the deployment will sync nothing.

### Writing rules

Rules query **canonical OCSF 1.9 paths only**:

| Concept | OCSF 1.9 path |
|---|---|
| Source / product | `metadata.log_source` |
| Event timestamp | `time` |
| Event class | `class_uid` (and `class_name`) |
| Activity within a class | `activity_id` (and `activity_name`) |
| Network endpoints | `src_endpoint.ip`, `dst_endpoint.ip`, `dst_endpoint.port`, `src_endpoint.hostname` |
| Acting user / subject user | `actor.user.name` / `user.name` |
| Process created / acting process | `process.name`, `process.cmd_line` / `actor.process.name`, `actor.process.cmd_line` |
| Files | `file.path`, `file.name`, `file.hashes.sha256` |
| HTTP | `http_request.url.url_string`, `http_request.http_method`, `http_response.code` |
| Volume | `traffic.bytes_in`, `traffic.bytes_out`, `traffic.packets_in`, `traffic.packets_out` |
| Reporting host | `device.hostname` |

Two things to keep in mind:

- **A non-canonical field is rejected, not ignored.** Former UDM names such as
  `source_type`, `timestamp`, `src_ip` or `command_line` fail validation with
  `did you mean <OCSF path>`; use `metadata.log_source`, `time`,
  `src_endpoint.ip` and `process.cmd_line`.
- **Enum ints have label siblings, and only the int is numeric.**
  `http_response.code` is the numeric HTTP status; `http_response.status` and
  `status` are label strings, so a comparison like `status >= 500` is a string
  compare and is silently empty.

### Demo rule set

`demo-ocsf/` contains a curated set of detections for demos and first-run
exploration, using fields such as `process.name`, `process.cmd_line`,
`src_endpoint.ip`, `dst_endpoint.hostname`, `actor.user.name`,
`device.hostname`, `api.operation` and `class_uid`.

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
metadata.log_source="okta"
| where condition="value"
| stats count() by field
| where count > threshold
```

## Advanced Features

These rules showcase nano's advanced detection capabilities:

### Sequence Detection
Detect ordered event chains (e.g., failed logins → success):
```
| sequence by user.name maxspan=5m [class_uid=3002 status_id=2] [class_uid=3002 status_id=1]
```

### Prevalence Filtering
Alert only on rare/new artifacts:
```
| prevalence enrich=true window=30d
| where prevalence_min < 5 AND prevalence_first_seen > now() - INTERVAL 24 HOUR
```

### Risk-Based Scoring
Dynamic risk calculation based on context:
```
| risk score=if(external_ip, 80, 40) entity=user.name factor="Login source"
```

## Contributing

1. Fork this repository
2. Create rules following the format above
3. Test in staging mode before submitting
4. Submit a pull request

## License

Detection Rule License (DRL) - See [LICENSE](LICENSE)

Rules may be used freely for detection purposes. Attribution required for redistribution.
