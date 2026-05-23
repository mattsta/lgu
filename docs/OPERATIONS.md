# Operations

## Purpose

This document explains how to run LGU in practice for:

- recent-traffic inspection
- batch reporting
- live alerting
- fail2ban integration
- routine operator workflows

## Operating Modes

### `log-audit`

Best for:

- reviewing the last few hundred or few thousand relevant log lines
- producing summary reports
- generating filtered raw log output
- tuning thresholds and detector configs

### `log-watch`

Best for:

- continuous live monitoring
- event emission
- fail2ban integration
- spotting new coordinated abuse quickly

## Installation and Runtime

### From a checkout

```bash
uv sync
uv run log-audit --help
uv run log-watch --help
```

### Installed tool

```bash
uv tool install .
log-audit --help
log-watch --help
```

## Typical Workflows

### Recent viable traffic

```bash
tail -n 2000 /var/log/nginx/access.log | uv run log-audit --recent-limit 100
```

### Narrow scope to a path family

```bash
tail -n 2000 /var/log/nginx/access.log | uv run log-audit --path-include '/(blog|posts|articles)/' --recent-limit 100
```

### Suspicious grouped traffic only

```bash
tail -n 5000 /var/log/nginx/access.log | uv run log-audit --path-include '/(blog|posts|articles)/' --bots-only
```

### Exact filtered raw lines

```bash
tail -n 5000 /var/log/nginx/access.log | uv run log-audit --path-include '/(blog|posts|articles)/' --raw-filtered-lines
```

This is a raw replay mode for downstream tools. It intentionally changes output from grouped operator view to original access-log lines. Use no output-mode flag for the normal grouped recent view, and add `--bots-only` to show grouped classified traffic instead.

### Output Mode Combinations

| Command shape                      | Output shape        | Shows                                    |
| ---------------------------------- | ------------------- | ---------------------------------------- |
| no output-mode flag                | grouped recent view | rows that survived classification        |
| `--bots-only`                      | grouped recent view | classified bot or excluded-provider rows |
| `--summary`                        | aggregate report    | totals, top suspects, and clean samples  |
| `--summary --bots-only`            | aggregate report    | classified IPs only                      |
| `--raw-filtered-lines`             | exact raw log lines | rows that survived classification        |
| `--raw-filtered-lines --bots-only` | exact raw log lines | classified bot or excluded-provider rows |

Provider exclusion is a classifier input. `--exclude-provider-traffic` changes which IPs are treated as classified traffic; it does not select an output format.

### Summary reporting

```bash
uv run log-audit /var/log/nginx/access.log --path-include '/(blog|posts|articles)/' --summary
```

## Live Monitoring

### Follow a file directly

```bash
uv run log-watch /var/log/nginx/access.log --follow
```

### Pipe from `tail -F`

```bash
tail -F /var/log/nginx/access.log | uv run log-watch
```

### JSON output

```bash
tail -F /var/log/nginx/access.log | uv run log-watch --output-format json
```

### Fail2ban-style output

```bash
tail -F /var/log/nginx/access.log | uv run log-watch --output-format fail2ban --alerts-log /var/log/lgu-alerts.log
```

## Fail2ban Integration

LGU should provide detection. Fail2ban should provide ban lifecycle management.

Recommended flow:

1. run `log-watch`
2. emit to a dedicated alerts log
3. point fail2ban at that log
4. let fail2ban manage ban, unban, bantime, and escalation

Included examples:

- `examples/fail2ban/log-watch.conf`
- `examples/fail2ban/jail.local.example`

## Log Rotation

### `log-watch --follow`

Direct follow mode watches inode changes and reopens the file when it rotates.

### `tail -F | log-watch`

This is also valid and delegates rotation handling to `tail`.

Choose one model and standardize operationally.

## Suggested Deployment Posture

For production use, run `log-watch` under a service manager such as:

- `systemd`
- `launchd`
- container supervision

Basic requirements:

- restart on failure
- stdout/stderr capture
- stable alert log path if using fail2ban
- explicit working directory and environment

## Tuning Strategy

### Start in batch mode

Before enabling live bans:

1. run `log-audit --summary`
2. inspect `log-audit --bots-only`
3. verify suspicious patterns look correct
4. tune thresholds and config
5. only then enable `log-watch`

### Tune by failure mode

If too many bots survive:

- lower sweep or serial thresholds
- add payload marker patterns
- extend known bot patterns

If too many humans are flagged:

- raise burst or streak thresholds
- narrow payload marker patterns
- review path scope

## Production Readiness Guidance

Good current fit:

- recent traffic introspection
- batch reporting
- live eventing at modest to moderate rates
- fail2ban enrichment

Not yet ideal for:

- extremely high-rate hostile traffic without careful tuning
- fully incremental high-scale streaming analytics

## Operational Safety Checklist

- detector config reviewed
- path scope verified
- live dry-run reviewed
- fail2ban reading a dedicated alert log
- service manager restart policy enabled
- log rotation tested
