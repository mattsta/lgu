# LGU: Log Ghoul Unmasker

LGU, the Log Ghoul Unmasker, is a command-line toolkit for reading web server access logs, filtering out obviously automated traffic, and surfacing the traffic that still looks plausibly human. It is built for the modern case where abusive crawlers do not identify themselves honestly, do not respect `robots.txt`, and often distribute their work across many IPs and spoofed user agents.

The Log Ghoul Unmasker has two primary entrypoints:

- `log-audit`: batch and slice analysis for recent traffic inspection, reporting, and filtering
- `log-watch`: live streaming analysis for alerting, operator visibility, and fail2ban integration

## Why

Why all this mess?

I still look at actual web server logs instead of using invasive javascript spyware everywhere. Except these days, web logs are full of thousands of bots pretending to be browsers just scraping sites redundantly over and over and over again.

When you look at the logs, you can kinda easily see the flow of bots: one IP accessing 1,000 pages all in 5 seconds, 20 IPs all with the same fake browser user agent or using a 17 year old browser user agent, clients using fake / simulated referrers so it looks like they "came from somewhere," and a couple other dozen cases.

Instead of visually filtering these out, I figured I'd try to collect all the "bad bot behaviors" I've seen into auto-correlating systems for live tagging and both live filtering out, live reporting, and generating live block lists of crawlers you can feed into other systems.

So, now here we have `lgu` as all of those combined.

Output in `--summary` mode looks nominally like:

```
top_suspects:
192.0.2.44	requests=43752	score=26005.0	burst=1698	unique_window=18	heads=0	streak=14	reasons=burst=1698/2.0s unique=18,paced-sweep=9621/45s unique=25 ref-dom=100%,repeated-pair	proof=174x first=22/Feb/2026:15:14:12 +0000 next=22/Feb/2026:15:14:12 +0000	ua=SyntheticBrowser/47.0 (43752)	referer=-
192.0.2.45	requests=27714	score=16664.0	burst=1287	unique_window=17	heads=0	streak=16	reasons=burst=1287/2.0s unique=17,paced-sweep=5774/45s unique=21 ref-dom=100%,repeated-pair	proof=93x first=24/Feb/2026:02:01:44 +0000 next=24/Feb/2026:02:01:44 +0000	ua=SyntheticBrowser/47.0 (27714)	referer=-
198.51.100.44	requests=5392	score=15167.0	burst=1168	unique_window=17	heads=0	streak=42	reasons=burst=1168/2.0s unique=17,paced-sweep=5252/45s unique=22 ref-dom=100%,fast-streak=42,repeated-pair	proof=30x first=15/Jan/2026:12:49:12 +0000 next=15/Jan/2026:12:49:12 +0000	ua=SyntheticBrowser/47.0 (5392)	referer=-
192.0.2.46	requests=25972	score=11647.0	burst=648	unique_window=18	heads=0	streak=12	reasons=burst=648/2.0s unique=18,repeated-pair	proof=89x first=23/Feb/2026:00:16:20 +0000 next=23/Feb/2026:00:16:20 +0000	ua=SyntheticBrowser/47.0 (25972)	referer=-
198.51.100.45	requests=9659	score=8474.0	burst=546	unique_window=13	heads=0	streak=14	reasons=burst=546/2.0s unique=13,paced-sweep=3167/45s unique=21 ref-dom=100%,repeated-pair	proof=56x first=24/Feb/2026:21:17:42 +0000 next=24/Feb/2026:21:17:42 +0000	ua=SyntheticBrowser/47.0 (9659)	referer=-
198.51.100.46	requests=13972	score=5297.0	burst=466	unique_window=14	heads=0	streak=13	reasons=burst=466/2.0s unique=14,paced-sweep=1737/45s unique=22 ref-dom=100%,repeated-pair	proof=67x first=21/Feb/2026:07:46:14 +0000 next=21/Feb/2026:07:46:15 +0000	ua=SyntheticBrowser/47.0 (13972)	referer=-
203.0.113.44	requests=85	score=152.0	burst=4	unique_window=4	heads=0	streak=8	reasons=known-ua-or-referer,paced-sweep=35/45s unique=14 ref-dom=100%,serial-sweep	proof=13 reqs 03-02 18:44:57..03-02 18:45:20 unique=13 ref=-	ua=SyntheticCrawler/1.4.8 (85)	referer=-
203.0.113.45	requests=75	score=150.9	burst=3	unique_window=3	heads=0	streak=5	reasons=known-ua-or-referer,paced-sweep=32/45s unique=32 ref-dom=100%,serial-sweep	proof=34 reqs 01-21 01:51:47..01-21 01:52:35 unique=34 ref=-	ua=SyntheticProbe/1.9.0 (75)	referer=-
203.0.113.46	requests=13	score=139.0	burst=13	unique_window=13	heads=0	streak=13	reasons=known-ua-or-referer,burst=13/2.0s unique=13,paced-sweep=13/45s unique=13 ref-dom=100%	proof=-	ua=SyntheticBot/2.1 (13)	referer=-
```

Output for the `watch` interface can be fed into automated blocking systems:

```
[04-08 11:19:39] BAN     ip=192.0.2.70 score=105.0 reasons=known-ua-or-referer ua=SyntheticCrawler/0.9 ref=-
[04-08 14:01:27] BAN     ip=192.0.2.71 score=105.0 reasons=known-ua-or-referer ua=SyntheticCrawler/0.5 ref=-
[04-08 14:10:31] BAN     ip=198.51.100.70 score=100.0 reasons=known-ua-or-referer ua=SyntheticCrawler/0.5 ref=-
[04-08 12:55:01] BAN     ip=198.51.100.71 score=105.0 reasons=known-ua-or-referer ua=SyntheticCrawler/0.5 ref=-
[04-08 13:29:53] BAN     ip=203.0.113.70 score=0.0 reasons=rapid-ua-switch ua=Firefox 67 / Win10 ref=-
[04-08 13:42:40] BAN     ip=203.0.113.71 score=105.0 reasons=known-ua-or-referer ua=SyntheticCrawler/0.5 ref=-
[04-08 13:54:54] BAN     ip=203.0.113.70 score=0.0 reasons=rotating-ua,rapid-ua-switch ua=Chrome 73 / Win10 ref=-
[04-08 14:28:09] BAN     ip=192.0.2.72 score=105.0 reasons=known-ua-or-referer ua=SyntheticCrawler/0.5 ref=-
```

## Documentation

The root stays small on purpose. Long-form project documentation lives in `docs/`.

- `README.md`: project overview, installation, quick start, and docs index
- `docs/ARCHITECTURE.md`: end-to-end system flow, detection pipeline, live decision model, and reporting architecture
- `docs/THREAT_MODEL.md`: adversaries, abuse classes, false-positive boundaries, and explicit non-goals
- `docs/DETECTORS.md`: detector catalog, evidence model, thresholds, and how detector families compose
- `docs/CONFIG.md`: detector configuration schema, merge semantics, layering rules, and examples
- `docs/OPERATIONS.md`: deployment guidance, live operation, fail2ban wiring, and operator ergonomics
- `docs/PERFORMANCE.md`: performance model, hot paths, current bottlenecks, and tuning guidance
- `docs/TESTING.md`: validation approach, fixture strategy, and correctness/performance checks
- `docs/CONTRIBUTING.md`: codebase expectations, review standards, and safe ways to extend detectors
- `docs/CHANGELOG.md`: release-oriented change history and notable project milestones

## Purpose

Traditional bot filtering often stops at user-agent regexes. The Log Ghoul Unmasker is built for the cases where that is not enough anymore.

The Log Ghoul Unmasker is designed to detect behavioral abuse patterns such as:

- rapid sequential archive walking
- paced serial sweeps that look human at a glance but are too regular to be real
- low-rate redundant revisits across the same article set
- distributed same-user-agent sweeps across many IPs
- distributed same-target same-user-agent fanout
- same-IP rapid user-agent switching
- repeated two-step fetch patterns across many sessions
- browser-like page loads that immediately pivot into exposed-file probing
- malformed referer fuzzing and parameter mutation
- injection-style probing and coordinated parameter-abuse campaigns

The goal is not only to classify traffic as suspicious. The goal is to help an operator answer:

- what was fetched
- when it was fetched
- from where it was fetched
- what user agent and referer were presented
- whether the activity should be ignored, watched, or blocked

## Vision

The Log Ghoul Unmasker is intended to be a practical public utility for site operators who want:

- a readable recent-traffic view instead of raw log spam
- behavior-based crawler detection instead of purely declarative bot lists
- a live alert stream that can feed other systems
- a configuration model that is generic by default and site-specific only when explicitly supplied

The design priority is:

1. keep the shipped defaults generic
2. let operators extend detection with loadable config instead of code edits
3. support both human-readable and machine-readable workflows
4. make live streaming output usable for automation systems such as fail2ban

## Safety and Limitations

LGU is designed to improve operator judgment, not to provide perfect attribution or perfect classification.

Important limits:

- it only sees access-log data
- some human behavior can still look machine-like
- some low-and-slow distributed crawlers can still evade current thresholds
- live mode is incremental for per-IP and distributed rolling windows, but still tuned for practical operator workloads rather than unbounded adversarial throughput

For the full threat and non-goal discussion, see `docs/THREAT_MODEL.md`.

## Installation

This project is a standard `uv` package.

### From a checkout

```bash
uv sync
uv run log-audit --help
uv run log-watch --help
```

### As a tool

```bash
uv tool install .
log-audit --help
log-watch --help
```

If `uv run` is being used in a fresh environment, the initial environment bootstrap may require network access to resolve build backend dependencies. After installation or environment creation, the console entrypoints can be run directly from the created environment.

## Project Layout

```text
src/lgu/audit.py                         Batch and slice analyzer
src/lgu/watch.py                         Live streaming analyzer
defaults/detector-config.json            Shipped runtime detector defaults
docs/                                   Project documentation set
docs/ARCHITECTURE.md                    System and decision-flow architecture
docs/DETECTORS.md                       Detector reference and taxonomy
docs/OPERATIONS.md                      Deployment and fail2ban operations
examples/fail2ban/log-watch.conf         Example fail2ban filter
examples/fail2ban/jail.local.example     Example fail2ban jail
examples/site-specific-detector-config.example.json
                                         Example site-specific override
```

## Quick Start

### 1. Inspect the most recent viable traffic

```bash
tail -n 2000 /var/log/nginx/access.log | uv run log-audit --recent-limit 100
```

### 2. Focus on a subset of paths

```bash
tail -n 2000 /var/log/nginx/access.log | uv run log-audit --path-include '/(blog|posts|articles)/' --recent-limit 100
```

### 3. Emit raw lines that survive classification

```bash
tail -n 5000 /var/log/nginx/access.log | uv run log-audit --path-include '/(blog|posts|articles)/' --raw-filtered-lines
```

### 4. Show only suspicious traffic in grouped form

```bash
tail -n 5000 /var/log/nginx/access.log | uv run log-audit --path-include '/(blog|posts|articles)/' --bots-only
```

### 5. Produce a summary report

```bash
uv run log-audit /var/log/nginx/access.log --path-include '/(blog|posts|articles)/' --summary
```

## `log-audit`

`log-audit` is the main batch analyzer. It supports:

- reading from a file or from `stdin`
- recent grouped view for operator inspection
- raw filtered-line replay
- summary reporting
- bot-only or clean-only selection
- configurable detector thresholds
- loadable detector config files

### Typical operator workflow

```bash
tail -n 2000 /var/log/nginx/access.log | uv run log-audit --path-include '/(blog|posts|articles)/' --recent-limit 100
```

This grouped recent view is the main “what are people fetching right now?” mode.

### Output modes

`log-audit` has three output shapes:

- default: grouped recent view, with bot-classified and excluded-provider traffic removed
- `--summary`: aggregate counts and top suspect/clean IP reports
- `--raw-filtered-lines`: original access-log lines that survive classification, intended for shell pipelines

`--bots-only` inverts the selected output mode. In the default grouped view, it shows grouped suspicious traffic. In raw replay mode, it emits the original raw lines for classified bot or excluded-provider traffic.

Common combinations:

| Command shape                                           | Output shape        | Shows                                        |
| ------------------------------------------------------- | ------------------- | -------------------------------------------- |
| `log-audit access.log`                                  | grouped recent view | traffic that survived bot/provider exclusion |
| `log-audit access.log --bots-only`                      | grouped recent view | classified bot or excluded-provider traffic  |
| `log-audit access.log --summary`                        | aggregate report    | suspect totals plus clean totals             |
| `log-audit access.log --summary --bots-only`            | aggregate report    | classified bot or excluded-provider IPs only |
| `log-audit access.log --raw-filtered-lines`             | exact raw log lines | traffic that survived bot/provider exclusion |
| `log-audit access.log --raw-filtered-lines --bots-only` | exact raw log lines | classified bot or excluded-provider traffic  |

`--exclude-provider-traffic` is not an output mode. It adds loaded provider-range matches to the classified set that these output modes use.

### Summary mode

```bash
uv run log-audit /var/log/nginx/access.log --path-include '/(blog|posts|articles)/' --summary --report-top 20 --campaign-report-top 10
```

### Raw filtered-line replay

```bash
uv run log-audit /var/log/nginx/access.log --path-include '/(blog|posts|articles)/' --raw-filtered-lines
```

`--raw-filtered-lines` changes the output shape from grouped view to exact original log-line replay.

## `log-watch`

`log-watch` is the live streaming analyzer. It continuously evaluates new requests, tracks rolling state, and emits alert transitions.

It supports:

- `human` output for operators
- `json` output for machine consumers
- `fail2ban` output for ban pipelines
- cooldowns to avoid repeat spam
- suspect and ban transitions
- periodic summaries in human mode

### Follow a live log

```bash
uv run log-watch /var/log/nginx/access.log --follow
```

### Emit JSON

```bash
tail -F /var/log/nginx/access.log | uv run log-watch --output-format json
```

### Emit fail2ban-friendly events

```bash
tail -F /var/log/nginx/access.log | uv run log-watch --output-format fail2ban --alerts-log /var/log/lgu-alerts.log
```

## Fail2ban Integration

The Log Ghoul Unmasker is intended to provide the detection layer. Fail2ban should handle the ban lifecycle.

Suggested flow:

1. run `log-watch` continuously
2. write emitted alert lines to a dedicated alert log
3. point fail2ban at that alert log
4. let fail2ban handle ban, unban, bantime, and escalation

Example files are included:

- `examples/fail2ban/log-watch.conf`
- `examples/fail2ban/jail.local.example`

For deployment and service-management guidance, see `docs/OPERATIONS.md`.

## Detector Configuration

The Log Ghoul Unmasker ships with a generic detector corpus in `defaults/detector-config.json`, including broad bot/crawler terms, common automated client libraries, and social preview fetcher product tokens that omit generic bot words.

Those signatures complement behavior detectors. Distributed exact-UA same-target bursts across different IPs are detected by `coordinated-target-fanout` even when the UA string is not in the known-bot config.

For full config details and merge semantics, see `docs/CONFIG.md`.

Operators can add one or more override files:

```bash
uv run log-audit access.log --detector-config ./my-detectors.json --detector-config ./team-detectors.json
```

Disable shipped defaults if needed:

```bash
uv run log-audit access.log --no-default-detector-config --detector-config ./my-detectors.json
```

### Config schema

```json
{
  "known_bot_any_patterns": ["syntheticcrawler", "syntheticprobe"],
  "known_bot_ua_patterns": ["syntheticexternalfetch"],
  "known_bot_referer_patterns": [],
  "payload_marker_patterns": [
    "(?:\\?|&)preview=true(?:[&#]|$)",
    "(?:\\?|&)render=full(?:[&#]|$)"
  ]
}
```

### Optional provider IP range enrichment

LGU does not vendor cloud/provider IP datasets. If an operator supplies one, LGU can enrich output and optionally apply provider-aware activity rules:

```bash
uv run log-audit access.log \
  --provider-ranges ./priv/cloud-provider-ip-addresses \
  --provider-watch '*' \
  --summary
```

To drop every request whose IP is in the loaded provider ranges from raw filtered-line replay:

```bash
uv run log-audit access.log \
  --provider-ranges ./priv/cloud-provider-ip-addresses \
  --exclude-provider-traffic \
  --raw-filtered-lines
```

To preview only the provider-hosted traffic that would be removed:

```bash
uv run log-audit access.log \
  --provider-ranges ./priv/cloud-provider-ip-addresses \
  --exclude-provider-traffic \
  --bots-only \
  --summary
```

Provider source adapters are intentionally pluggable. Built-in adapters cover:

- plain text CIDR files
- normalized CSV files with `cidr,provider,service,region`
- normalized JSON records
- local `cloud-provider-ip-addresses` style repositories

Provider membership is not a bot verdict by itself unless `--exclude-provider-traffic` is set. Without that flag, provider data is enrichment only, and provider-hosted activity proofs only run for providers explicitly named with `--provider-watch`.

### Config fields

- `known_bot_any_patterns`: regexes tested against both user agent and referer
- `known_bot_ua_patterns`: regexes tested only against user agent
- `known_bot_referer_patterns`: regexes tested only against referer
- `payload_marker_patterns`: regexes tested against request paths and query strings for suspicious parameter-abuse families

The bundled example override file is:

- `examples/site-specific-detector-config.example.json`

That file intentionally demonstrates how to add site-specific markers without hardcoding them into the codebase.

## Detection Model

The shipped behavior detectors currently include:

- burst and fast-streak detection
- paced serial sweeps
- `HEAD` storms
- coordinated same-UA multi-IP sweeps
- repeated same-IP page-pair sessions
- tight same-IP multi-page fetch clusters
- rotating and rapidly switching user agents
- cadenced same-path repeat fetches, including near-hour two-hit repeats
- periodic pollers
- payload-marker abuse
- malformed referer fuzzing
- injection-style request probes
- distributed payload campaigns

These are intentionally layered:

- some detectors are signature-based
- some detectors are time-window based
- some detectors are cross-IP campaign detectors

## Output Modes

### Human-readable grouped view

Best for recent traffic inspection.

Shows:

- grouped requests by IP and user agent
- request sequence numbers
- compact timestamps
- method and status
- truncated path
- compact referer
- optional raw user agent

### JSON live output

Best for:

- pipelines
- dashboards
- post-processing
- SIEM ingestion

### Fail2ban output

Best for:

- ban automation
- recidive escalation through existing fail2ban facilities

## Performance Notes

The Log Ghoul Unmasker is optimized for the operator workflows it is intended to serve:

- recent-slice analysis from `tail -n ...`
- scoped full-file analysis
- live streaming from `tail -F` or direct file follow

The analyzer includes:

- parse-once collection for batch mode
- memoized string classification for hot paths
- a unified payload-campaign pass
- careful avoidance of fake parallel speedups when process pools are unavailable

For practical usage, the most common and cheapest workflow remains:

```bash
tail -n 2000 /var/log/nginx/access.log | uv run log-audit --recent-limit 100
```

For the current performance model and bottlenecks, see `docs/PERFORMANCE.md`.

## Development

### Sync the environment

```bash
uv sync
uv sync --group dev
```

### Run the CLI entrypoints

```bash
uv run log-audit --help
uv run log-watch --help
```

### Compile-check

```bash
uv run python -m py_compile src/lgu/audit.py src/lgu/watch.py
```

For testing and contribution guidance, see:

- `docs/TESTING.md`
- `docs/CONTRIBUTING.md`

## Release Direction

This project is intended to remain:

- generic by default
- configurable by data files
- useful both interactively and in automation
- conservative about hiding traffic without evidence

Likely future work:

- more structured detector configuration
- optional CIDR and ASN-aware heuristics
- better packaged sample datasets
- benchmark and regression harnesses
- richer machine-readable summary output

## Status

This is an early release-oriented version of the project. The interfaces are already usable, but detector tuning and packaged release polish should be expected to continue.
