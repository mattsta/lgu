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

### Reverse DNS names in the grouped view

The grouped view prints a `ptr` line under each IP and caches every answer on disk, so a given address costs one lookup ever, not one per run.

```bash
# Host-wide shared cache so every operator on the box reuses the same answers.
export LGU_PTR_CACHE=/var/cache/lgu/ptr-cache.json
tail -n 2000 /var/log/nginx/access.log | uv run log-audit --recent-limit 100
```

Disable lookups on hosts with no outbound DNS, or when analyzing logs from a network you do not want to query:

```bash
tail -n 2000 /var/log/nginx/access.log | uv run log-audit --no-reverse-dns
```

Only IPs shown in the grouped view are resolved, so `--summary`, `--raw-filtered-lines`, and `log-watch` never emit DNS traffic. Treat PTR names as an operator reading aid: the address owner controls the record, and no detector uses it.

### Registry owners (whois) in the grouped view

Under `ptr`, the grouped view prints an `org` line. It shows the registered owner of the network block, the CIDR containing the IP, the network name when it carries information, and the registry that answered:

```text
192.0.2.10       Chrome 139 / Linux
                 ptr -
                 org Synthetic Hosting LLC  192.0.2.0/24  SYN-HOSTING-BLK  [ARIN]
```

When the registry lists no assignee for a block, the line falls back to the registry itself, for example `org LACNIC (no assignee listed)  198.51.100.0/24`. Numbering-plan noise such as numeric network names or address-range handles is hidden. National registries are named when they answer, for example `[NIC.br]` under LACNIC.

The line always says why it is empty:

| `org` text                   | Meaning                                                                                                                                                                                        |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-`                          | the registry was asked and has no record, or the address is not global                                                                                                                         |
| `? deferred: <reason>`       | not asked this run (budget used, published hourly limit reached, or a registry refusal whose pause outlasts the run); the reason names the HTTP status the registry sent; a later run fills it |
| `? <registry> lookup failed` | the query was sent and failed (timeout, server error)                                                                                                                                          |

Lookups use RDAP, the JSON successor to port-43 whois. IANA's RDAP bootstrap table routes each address straight to the authoritative registry (ARIN, RIPE NCC, APNIC, LACNIC, or AFRINIC). Each registry is paced separately. Registries still redirect some transferred space to each other (about one in ten ARIN-routed lookups in recorded probes); a redirected answer or refusal is charged to the registry that actually sent it. The bootstrap table is cached next to the owner cache and refreshed weekly. Only HTTPS redirects are followed, and registry text is stripped of control characters before printing.

Pacing follows what the registries publish:

- **LACNIC** documents per-IP limits of 10 queries per minute and 1000 per hour. LGU holds itself to 9 and 900. Request times are persisted in the cache, so back-to-back runs share one budget, and a minute-window wait is slept while an hour-window wait defers to a later run.
- **ARIN, RIPE NCC, APNIC, and AFRINIC** publish no numeric RDAP query rate. These registries are spaced `--whois-interval` seconds apart (default `0.5`), each independently.
- **RIPE NCC personal-data cap:** RIPE's Acceptable Use Policy allows 1,000 personal data sets (person and role objects) per IP address per 24 hours, and every RDAP network answer from RIPE embeds its admin, tech, and abuse contacts (only e-mail is redacted), so each lookup spends several. Over the cap, RIPE blocks the host until the end of the UTC day; being blocked several times, or querying while blocked, makes the block permanent. RIPE reports the block as HTTP 429 with `%ERROR:201: access denied`. LGU classifies that as a block, never retries it, and persists it: a temporary block until 00:00 UTC, a permanent one until you ask the RIPE NCC database team to lift it (the contact is linked from the error text `lgu-whois-probe explain` prints) and then run `lgu-whois-probe clear-denial RIPE`. Addresses another registry redirected to RIPE are remembered, so they are not re-sent while RIPE blocks the host. `lgu-whois-probe burst` also refuses a blocked registry unless given `--force`.
- **Throttling:** RDAP servers signal throttling with HTTP 429 and an optional `Retry-After` (RFC 7480). A 429, or a 403/503 that carries `Retry-After`, pauses only the registry that actually sent it (after redirects, the answering registry, not the one first asked). The pause is `Retry-After` when present. Otherwise it starts at 2 seconds and doubles with each consecutive refusal, resetting on the next answer; a streak older than an hour starts over. Registry pauses up to 10 seconds are slept and the same IP is retried (up to 4 attempts, so a registry that keeps refusing costs at most about 14 seconds per run); longer pauses defer. The pause, streak, and the refusal behind it (status, `Retry-After`, URL) are persisted, so later runs respect them and `lgu-whois-probe explain` shows what caused them.
- **Spacing:** the per-registry `--whois-interval` is always slept, never deferred, whatever its length.
- **Access denied:** a 403 without `Retry-After` is an access decision, not pacing. It is reported as `? <registry> denied access (HTTP 403, no Retry-After)` and counts as a failure; it never creates a pause.
- **Failures:** three failures in a row (transport errors, server errors, or bare 403s) from one registry pause it for the rest of the run. Failures are never cached and never persist a pause.

Other safeguards:

- Answers are cached by network range, not by IP. One query covers every address in that block, in this run and later ones.
- Each run makes at most `--whois-max-lookups` new queries (default `100`). The newest IPs get them first, and a stderr note summarizes anything deferred.
- Private, loopback, documentation, and other non-global addresses are never sent.

#### Validating pacing with `lgu-whois-probe`

Pacing decisions should be argued from recorded registry responses, not assumptions. `lgu-whois-probe` sends requests through the same fetch and classification code as `--whois` and appends every exchange (HTTP status, all headers, final URL after redirects, latency, the complete response body with RDAP error fields extracted, and how the resolver classified it) to `whois-probe.jsonl` next to the cache. Run it on the host that shows the problem, because registries and CDNs judge the client IP.

```bash
uv run lgu-whois-probe explain                         # offline: why the current cache defers the next query, per registry
uv run lgu-whois-probe burst ARIN --count 30           # production spacing until the first refusal
uv run lgu-whois-probe replay --sample ARIN=60 --check # real resolver on a scratch cache; exit 1 on any unbacked deferral
uv run lgu-whois-probe replay --cache ~/.cache/lgu/whois-cache.json --sample ARIN=20  # reproduce this host's state, read-only
uv run lgu-whois-probe summary --since-hours 24        # per-registry status, refusals, and the load before each one
```

`replay` copies the cache it starts from and never writes it. Each refusal in `summary` lists the gap since the previous request and the request counts in the prior minute and hour, so a real limit shows up as a consistent threshold across runs.

```bash
uv run lgu-whois-probe entities                        # offline: how each recorded answer's registrants were judged
uv run lgu-whois-probe crosscheck --from-evidence      # offline: recorded RDAP answers vs the local dataset, re-parsed
uv run lgu-whois-probe crosscheck --sample 20          # live: local dataset vs RDAP field by field (costs RIPE quota)
```

#### Local registry datasets (`lgu-whois-data`)

Owners are resolved from the best source available, in order:

1. **Local registry dataset** built from the registry's published bulk database dump. No network, no query limits, no personal data retrieved.
2. **The owner cache** of earlier RDAP answers.
3. **Live RDAP**, paced and back-off-aware as above, skipping any registry that has blocked this host.

RIPE NCC is the first dataset. Its daily dumps (the `inetnum`, `inet6num`, and `organisation` split files, about 260 MB compressed) have personal data removed, so using them costs nothing against RIPE's personal-data cap and works even while RIPE blocks the host's queries.

```bash
uv run lgu-whois-data sync        # download changed dumps (If-Modified-Since) and rebuild the index
uv run lgu-whois-data info        # what is built, from which publication
uv run lgu-whois-data lookup <ip> # answer from the local index, with lookup time
```

Run `sync` from cron, daily or weekly; unchanged dumps are not re-downloaded and the index is only rebuilt when they change. A build takes a few minutes and a few hundred MB of memory, and leaves a read-only SQLite index (about 750 MB for RIPE) under `$LGU_WHOIS_DATA`, else a `whois-data` directory next to the owner cache. `log-audit --whois-data DIR` points elsewhere and `--whois-data none` disables it.

How the index answers:

- Ownership is nested (allocation, sub-allocation, assignment). The build flattens it into disjoint segments labelled with the most specific owner, so each lookup is one indexed probe, typically tens of microseconds, with nothing loaded per run. The answer is the same block RDAP returns.
- Placeholder objects for space the registry does not manage (RIPE's `IANA-BLK` and `NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK`) are dropped, so the dataset only answers for addresses the registry actually holds, including space transferred in from another region (which ARIN would otherwise redirect).
- The owner shown is the object's organisation (`org:` → `org-name`); without one, the network name. Maintainer accounts are never shown as owners, from either the dataset or RDAP.
- A dataset is used whatever its age: network ownership changes slowly, and an old dump still beats a query. `lgu-whois-probe explain` shows when each dataset was published.
- Dataset answers are never copied into the owner cache.

The cache lives at `$LGU_WHOIS_CACHE`, else `$XDG_CACHE_HOME/lgu/whois-cache.json`, else `~/.cache/lgu/whois-cache.json`. Owners stay valid for `--whois-cache-ttl` seconds (default 30 days). Not-found answers are retried after a day. `--whois-cache none` looks up without persisting, and `--no-whois` turns the line off. Like PTR, only the grouped view queries, and no detector uses the answer.

### Narrow scope to a path family

```bash
tail -n 2000 /var/log/nginx/access.log | uv run log-audit --show-path '^/(blog|posts|articles)/' --recent-limit 100
```

### Suspicious grouped traffic only

```bash
tail -n 5000 /var/log/nginx/access.log | uv run log-audit --show-path '^/(blog|posts|articles)/' --bots-only
```

### Exact filtered raw lines

```bash
tail -n 5000 /var/log/nginx/access.log | uv run log-audit --show-path '^/(blog|posts|articles)/' --raw-filtered-lines
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
uv run log-audit /var/log/nginx/access.log --show-path '^/(blog|posts|articles)/' --summary
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

With `--emit-suspects`, suspects are written as `action=suspect` so the shipped filter, which matches `action=ban`, ignores them. `--fail2ban-action` only renames real bans.

## Reporting on Selected Paths

Give LGU the whole log and name the paths you want reported:

```bash
tail -n 10000 /var/log/nginx/access.log | uv run log-audit --show-path '^/(blog|posts|articles)/'
```

`--show-path` runs after analysis and is repeatable. Filtering first with `rg`, `grep`, or `--path-include` removes favicon and asset requests, so nothing can be confirmed as a browser, and it hides each client's other traffic from every detector. LGU prints a note on stderr and drops the visit labels when no reported client has browser evidence.

`--recent-limit` counts shown rows, and `#` numbers still refer to the full input. In `--summary`, the top lists cover clients with at least one shown request, with their totals across all traffic, and `visitor_breakdown` counts shown requests only.

## Reading the Human View

The default batch view is the traffic LGU could not attribute to software. Three tools help judge it:

```bash
# Who is left, and which signals hid the rest.
uv run log-audit access.log --summary

# Why each hidden client was hidden.
uv run log-audit access.log --bots-only

# Only clients that rendered a page.
uv run log-audit access.log --confirmed-only
```

Each grouped client carries `visit=confirmed`, `visit=split`, or `visit=unconfirmed`; see [DETECTORS.md](DETECTORS.md#visit-tiers). `--bots-only` adds a `why` line naming the proofs that hid the client.

`--confirmed-only` depends on subresource requests reaching this log. Behind a CDN that serves assets and favicons itself, real visitors stay `unconfirmed`, so leave it off.

Before adopting a new signal or cutoff, read the rows it removes rather than the count. `sole_signal_ips` in `--summary` counts clients hidden by exactly one signal, where a mistaken rule costs a real visitor. `--sole-signal` shows those clients:

```bash
uv run log-audit access.log --sole-signal protocol-mismatch
```

## Clients Behind a CDN or Proxy

If the first log field is your CDN edge and the real client is logged in a trailing quoted field, per-IP detectors see the edge rather than the visitor. Name the proxy networks you trust:

```bash
uv run log-audit access.log --trusted-proxy 192.0.2.0/24 --trusted-proxy 198.51.100.0/24
```

The same flag works for `log-watch`. LGU only uses the forwarded address when the connecting peer is inside a listed network, and reads a comma-separated list from the right, skipping trusted and internal hops, because left-hand entries are supplied by the client. Without the flag the forwarded field is ignored. List every edge range: rows from an unlisted edge keep that edge as their client.

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
