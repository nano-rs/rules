# nano Detection Rules

Official detection rule repository for [nano](https://nano.rs). These rules are written in native nPL (nano Pipe Language) format and can be synced directly into your nano deployment.

## Usage

Add this repository in nano:

1. Navigate to **Settings → Rule Repositories**
2. Click **Add Repository**
3. Enter:
   - **URL**: `https://github.com/nano-rs/rules`
   - **Branch**: `main`, or `ocsf-1.9` if your deployment runs OCSF 1.9 on the
     Iceberg/chDB lake — see [Branches and OCSF versions](#branches-and-ocsf-versions)
   - **Format**: nano (nPL)
4. Click **Sync** to fetch rules
5. Browse and import rules as needed

## Repository Structure

```
├── collection/                  # Data collection, staging, capture
├── collection-ocsf/
├── command_control/             # C2 communications, beaconing
├── command_control-ocsf/
├── credential_access/           # Credential theft, brute force, dumping
├── credential_access-ocsf/
├── defense_evasion/             # Obfuscation, indicator removal
├── defense_evasion-ocsf/
├── discovery/                   # Network/system enumeration
├── discovery-ocsf/
├── execution/                   # Script execution, command-line abuse
├── execution-ocsf/
├── exfiltration/                # Data theft, staging, transfer
├── exfiltration-ocsf/
├── impact/                      # Ransomware, wipers, destruction, hijacking
├── impact-ocsf/
├── initial_access/              # Phishing, exploitation, valid accounts
├── initial_access-ocsf/
├── lateral_movement/            # Remote services, pass-the-hash
├── lateral_movement-ocsf/
├── persistence/                 # Scheduled tasks, registry, services
├── persistence-ocsf/
├── privilege_escalation/        # Token abuse, UAC bypass, escalation
├── privilege_escalation-ocsf/
├── demo/                        # Curated demo rules (UDM schema)
└── demo-ocsf/                   # The same demo rules, OCSF schema
```

### Schema pairing: `<tactic>/` and `<tactic>-ocsf/`

Every rule set exists twice, once per schema:

- **`<tactic>/`** holds the detections written against nano's **UDM** schema
  (`src_ip`, `process_name`, `command_line`, `source_type`, `timestamp`, …).
- **`<tactic>-ocsf/`** holds the *same detections*, translated to **OCSF**.
  Same filenames, same frontmatter (title, severity, mode, schedule, lookback,
  MITRE mapping, tags, AI triage hints) — only the nPL body differs.

A deployment running `NANO_SCHEMA_PROFILE=ocsf` automatically syncs the `-ocsf`
sibling instead of the UDM folder. That resolution is **built into nano**: it
takes the first path segment of a rule's folder and appends `-ocsf` to find the
OCSF variant, so `impact` resolves to `impact-ocsf`. This is why the naming
convention is not a matter of taste — a nested `ocsf/` tree, a version-suffixed
folder such as `impact-ocsf-1.9/`, or any other shape will simply never be
found, and the deployment will sync nothing.

### Branches and OCSF versions

The folder layout says *which schema*; the **branch says which OCSF version**.

| Branch | OCSF version | Intended deployment |
|---|---|---|
| `main` | **OCSF 1.8** | OCSF running on ClickHouse |
| `ocsf-1.9` | **OCSF 1.9** | The Iceberg/chDB lake |

Point the rule repository's `branch` setting at whichever matches the
deployment. It is a per-deployment config field, so moving a tenant from 1.8 to
1.9 is a one-field change with no code involved. The UDM folders are carried on
both branches and are unaffected by the choice.

**The two are not interchangeable.** OCSF 1.9 enforces canonical field names: a
1.8-era rule that still says `source_type=` or `timestamp` is **rejected
outright** with `Unknown canonical OCSF field`, rather than running and quietly
returning nothing. If you are migrating, that is the single most important
sentence here — every rule has to be re-run against the target deployment
before it is trusted, and a rule that fails to run is loud, not silent.

### Writing OCSF 1.9 rules (`ocsf-1.9` branch)

On the `ocsf-1.9` branch the `-ocsf` rule sets query **canonical OCSF 1.9 paths
only**:

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

- **A non-canonical field is rejected, not ignored.** `source_type` and
  `timestamp` do not exist in OCSF; use `metadata.log_source` and `time`.
- **Enum ints have label siblings, and only the int is numeric.**
  `http_response.code` is the numeric HTTP status; `http_response.status` and
  `status` are label strings, so a comparison like `status >= 500` is a string
  compare and is silently empty.

### Demo rule sets

`demo/` and `demo-ocsf/` contain the same curated detections in two schema
flavours. Import the set that matches your deployment's schema profile:

- **`demo/`** — for the default UDM schema (fields like `process_name`,
  `command_line`, `src_host`, `src_ip`, `event_type`).
- **`demo-ocsf/`** — for deployments running the OCSF schema profile
  (`NANO_SCHEMA_PROFILE=ocsf`). Queries use OCSF fields such as `process.name`,
  `process.cmd_line`, `src_endpoint.ip`, `dst_endpoint.hostname`,
  `actor.user.name`, `device.hostname`, `api.operation` and `class_uid`. As
  everywhere else in this repository, the branch decides the OCSF version — take
  `demo-ocsf/` from `main` for OCSF 1.8 on ClickHouse, or from `ocsf-1.9` for
  the 1.9 lake.

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
