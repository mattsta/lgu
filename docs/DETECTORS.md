# Detectors

## Purpose

This document describes LGU’s detector surface, how detectors are grouped, what they consume, and what they emit.

LGU uses two broad classes of detectors:

- heuristic detectors that contribute to per-IP classification through `IPStats`
- proof detectors that emit explicit `ForcedProof`s

The final effective bot decision is the union of both paths.

## Decision Semantics

LGU uses three action labels in live mode and two main visibility labels in batch mode.

### Batch semantics

- `clean`: traffic that did not trip the heuristic bot path and did not receive any forced proof
- `bot`: traffic that either tripped heuristic bot classification or received one or more forced proofs

### Live semantics

- `clean`: no output event; the current row did not push the IP into a suspicious state
- `suspect`: the IP is suspicious enough to surface to an operator, but not yet strong enough for an automatic ban event
- `ban`: the IP crossed a strong threshold, usually through a strong proof or a very high heuristic score

### Why score and proofs can disagree

Some detectors intentionally emit explicit proofs even when a simple aggregate score is modest.

Examples:

- same-second UA swapping
- coordinated multi-IP same-UA sweeps
- payload-fuzzing campaigns

Those are treated as stronger evidence than a plain count-based score because the pattern itself is machine-like.

## Detector Layers

### Layer 1: Heuristic aggregation

Outputs:

- `IPStats`
- `IPStats.score()`
- `IPStats.is_bot()`
- heuristic reason strings

### Layer 2: Per-IP proof detectors

Outputs:

- explicit `ForcedProof` records by IP

### Layer 3: Cross-IP campaign detectors

Outputs:

- explicit `ForcedProof` records by IP
- campaign summaries for reporting

## How Detector Signals Combine

LGU is not a bag of unrelated checks. The detectors combine in two distinct paths.

### Path 1: Heuristic conjunctions inside `IPStats`

The heuristic path is IP-scoped and counter-driven.

Each heuristic detector maintains rolling or aggregate state, and then `IPStats.is_bot()` applies specific conjunctions:

- known bot pattern:
  - any configured regex matches raw UA or raw referer
- burst:
  - `max_burst >= burst_count`
  - and `max_unique_paths_window >= unique_paths`
- HEAD burst:
  - `max_heads_window >= head_burst`
  - and `max_unique_paths_window >= head_unique_paths`
- paced sweep:
  - `max_paced_sweep >= sweep_count`
  - and `max_paced_sweep_unique_paths >= sweep_unique_paths`
  - and `max_paced_sweep_dominant_referer_ratio >= sweep_dominant_referer_ratio`
- fast streak:
  - `max_small_gap_streak >= streak_count`
  - and `distinct_paths_total >= streak_unique_total`

So the heuristic path is not “score only.” It has explicit hard bot conditions as well as a score used for ranking and live suspect/ban thresholds.

### Path 2: Proof union

Proof detectors emit `ForcedProof` records. A proof does not incrementally nudge a score. It contributes explicit evidence that is later unioned by IP.

That means:

- one IP can look numerically mild in heuristics
- but still become suspicious or banned because it received a strong proof

### Final effective bot decision

Batch mode:

- `effective_bot(ip) = heuristic_bot(ip) OR has_forced_proof(ip)`

Live mode:

- heuristics produce a score and heuristic reasons
- proofs produce explicit proof kinds
- live action is then chosen from:
  - `clean`
  - `suspect`
  - `ban`

Strong proof kinds directly force `ban` in live mode.
The canonical detector list lives in `src/lgu/detector_catalog.py`; tests compare scenario coverage, threshold arguments, config dependencies, and live coverage requirements against that catalog so docs, live behavior, and proof expectations do not drift silently.

## Detector Matrix

| Detector                  | Class          | Scope    | Primary evidence                                                      | Output                                | Typical strength                |
| ------------------------- | -------------- | -------- | --------------------------------------------------------------------- | ------------------------------------- | ------------------------------- |
| Known bot pattern         | Heuristic      | Per-IP   | UA / referer regex match                                              | Immediate bot via `matched_known_bot` | High when signatures are honest |
| Burst                     | Heuristic      | Per-IP   | Request count + unique paths in short window                          | Bot via `IPStats.is_bot()`            | High for obvious crawlers       |
| HEAD burst                | Heuristic      | Per-IP   | HEAD density + unique paths                                           | Bot via `IPStats.is_bot()`            | High for scanners               |
| Paced sweep               | Heuristic      | Per-IP   | Longer window + unique paths + dominant referer ratio                 | Bot via `IPStats.is_bot()`            | Good for steady walkers         |
| Fast streak               | Heuristic      | Per-IP   | Small gaps across path changes                                        | Bot via `IPStats.is_bot()`            | Good for dense path walks       |
| Repeated pair             | Proof          | Per-IP   | Same `(path A -> path B)` repeated many times                         | `ForcedProof`                         | High for synthetic sessions     |
| Tight multi-fetch         | Proof          | Per-IP   | Compact cluster of repeated or same-second content path fetches       | `ForcedProof`                         | High for synthetic fetch groups |
| Asset-primed probe        | Proof          | Per-IP   | Page dependency load followed by exposed-file probes                  | `ForcedProof`                         | High for disguised scanners     |
| Redundant revisit         | Proof          | Per-IP   | Same base paths revisited repeatedly with dominant referer shape      | `ForcedProof`                         | High for low-rate crawlers      |
| Low-context revisit       | Proof          | Per-IP   | Same content target refetched with only direct/root referer context   | `ForcedProof`                         | High for repeated fetchers      |
| Rotating UA               | Proof          | Per-IP   | Many distinct UAs and UA families                                     | `ForcedProof`                         | Medium to high                  |
| Cadenced repeat           | Proof          | Per-IP   | Same content path revisited on a stable long-gap or near-hour cadence | `ForcedProof`                         | High for scheduled fetchers     |
| Periodic poller           | Proof          | Per-IP   | Same path at regular intervals                                        | `ForcedProof`                         | High for pollers                |
| Serial sweep              | Proof          | Per-IP   | Ordered path walk with bounded gaps                                   | `ForcedProof`                         | High for crawlers               |
| Payload fuzzer            | Proof          | Per-IP   | Payload markers + mutation / referer junk / injection                 | `ForcedProof`                         | High                            |
| Same-second UA swap       | Proof          | Per-IP   | Same-second mutated twins with different UAs                          | `ForcedProof`                         | Very high                       |
| Rapid UA switch           | Proof          | Per-IP   | Small window with multiple UAs and UA families                        | `ForcedProof`                         | High                            |
| Coordinated UA            | Proof          | Cross-IP | Same UA across many IPs and paths                                     | `ForcedProof`                         | High                            |
| Coordinated target fanout | Proof          | Cross-IP | Same coarse UA family or exact UA, same base path, many IPs           | `ForcedProof`                         | High                            |
| Low-context fanout        | Proof          | Cross-IP | Same content target, many shallow IPs, direct/root referer context    | `ForcedProof`                         | High for distributed fetchers   |
| Payload campaign          | Proof + report | Cross-IP | Shared payload family with enough IP and path diversity               | `ForcedProof` + summary               | High                            |
| Provider-hosted activity  | Optional proof | Provider | Opt-in provider CIDR attribution plus request/path thresholds         | `ForcedProof` when enabled            | Context-dependent               |

## Signal Dimension Matrix

This matrix is the quickest way to see what each detector actually reads.

| Detector                  | Time                                  | IP                               | UA                                | Path / URL                                        | Referer                         | Method                               | Status       |
| ------------------------- | ------------------------------------- | -------------------------------- | --------------------------------- | ------------------------------------------------- | ------------------------------- | ------------------------------------ | ------------ |
| Known bot pattern         | No window                             | Same IP only as aggregation unit | Yes                               | No                                                | Yes                             | No                                   | No           |
| Burst                     | Short window                          | Same IP                          | No                                | Yes                                               | No                              | Yes indirectly through request count | No           |
| HEAD burst                | Short window                          | Same IP                          | No                                | Yes                                               | No                              | Yes, explicitly HEAD                 | No           |
| Paced sweep               | Longer window                         | Same IP                          | No                                | Yes                                               | Yes, dominant referer ratio     | Yes indirectly through request count | No           |
| Fast streak               | Inter-request gaps                    | Same IP                          | No                                | Yes                                               | No                              | No                                   | No           |
| Repeated pair             | Adjacent gaps                         | Same IP                          | No                                | Yes, ordered pairs                                | No                              | No                                   | No           |
| Tight multi-fetch         | Short content cluster                 | Same IP                          | No                                | Yes, repeated or same-second base paths           | Yes, dominant referer ratio     | No                                   | No           |
| Asset-primed probe        | Short page-load/probe window          | Same IP                          | Same IP aggregation only          | Yes, page dependencies plus exposed-file probes   | Yes, same-page asset referers   | No                                   | No           |
| Redundant revisit         | Whole IP slice with revisits          | Same IP                          | No                                | Yes, repeated base paths                          | Yes, dominant referer ratio     | No                                   | No           |
| Low-context revisit       | Whole IP slice with span check        | Same IP                          | No                                | Yes, same content base path                       | Yes, direct/root only           | Yes, requires GET                    | Yes, 2xx/3xx |
| Rotating UA               | Whole IP slice/window                 | Same IP                          | Yes                               | No                                                | No                              | No                                   | No           |
| Cadenced repeat           | Long-gap stable cadence               | Same IP                          | No                                | Yes, same base path                               | Yes, dominant referer ratio     | No                                   | No           |
| Periodic poller           | Repeated intervals                    | Same IP                          | No                                | Yes, same path                                    | No                              | Yes, summarized in proof detail      | No           |
| Serial sweep              | Ordered bounded gaps                  | Same IP                          | No                                | Yes, path changes and unique paths                | Yes, summarized in proof detail | No                                   | No           |
| Payload fuzzer            | Short mutation gaps plus slice totals | Same IP                          | No                                | Yes, payload marker / mutation / injection        | Yes, malformed referer          | No                                   | No           |
| Same-second UA swap       | Same second                           | Same IP                          | Yes                               | Yes, same base path mutated twins                 | No                              | No                                   | No           |
| Rapid UA switch           | Small window                          | Same IP                          | Yes, distinct UAs and families    | Yes, base paths counted                           | No                              | No                                   | No           |
| Coordinated UA            | Sliding cross-IP window               | Many IPs                         | Yes, same raw UA                  | Yes, unique paths                                 | No                              | No                                   | No           |
| Coordinated target fanout | Sliding cross-IP window               | Many IPs                         | Yes, same coarse family or raw UA | Yes, same repeated base path                      | Yes, dominant referer ratio     | No                                   | No           |
| Low-context fanout        | Long sliding cross-IP window          | Many shallow IPs                 | Yes, dominant UA family           | Yes, same content base path                       | Yes, direct/root only           | Yes, requires GET                    | Yes, 2xx/3xx |
| Payload campaign          | Sliding cross-IP window               | Many IPs                         | No                                | Yes, payload family + target profile + base paths | Yes, via family classification  | No                                   | No           |
| Provider-hosted activity  | Whole provider-attributed IP slice    | Provider CIDR match              | No                                | Yes, unique paths                                 | No                              | No                                   | No           |

## Heuristic Detectors

### Known Bot Pattern Match

Inputs:

- raw UA
- raw referer
- detector-config `known_bot_any_patterns`
- detector-config `known_bot_ua_patterns`
- detector-config `known_bot_referer_patterns`
- CLI `--bot-pattern` additions

Effect:

- `matched_known_bot` becomes true
- `IPStats.is_bot()` returns true
- score gets a large boost

Good at:

- obvious bots
- script clients
- feed readers

Weak at:

- disguised browser-like bots

Exact logic:

- for each row of an IP, test all configured known-bot pattern lists
- patterns are split by field:
  - `known_bot_any_patterns` test both raw UA and raw referer
  - `known_bot_ua_patterns` test only raw UA
  - `known_bot_referer_patterns` test only raw referer
- if any match occurs for any row of that IP:
  - `matched_known_bot = True`
  - score receives a large fixed boost
  - `IPStats.is_bot()` becomes immediately true

### Burst

Inputs:

- short rolling event window
- unique path count in that window

Thresholds:

- `--window-seconds`
- `--burst-count`
- `--unique-paths`

Good at:

- short crawl storms

Exact logic:

- maintain a short rolling window of recent events for one IP
- track:
  - total requests in window
  - unique paths in window
- update maxima over the whole IP slice
- heuristic bot condition fires only when both are true:
  - request count threshold met
  - unique path threshold met

### HEAD Burst

Inputs:

- short rolling event window
- HEAD count
- unique path count

Thresholds:

- `--head-burst`
- `--head-unique-paths`

Good at:

- metadata or header-first scanners

Exact logic:

- uses the same short rolling window as burst detection
- tracks:
  - HEAD count in window
  - unique paths in window
- heuristic bot condition fires only when both are true:
  - HEAD threshold met
  - unique path threshold met

### Paced Sweep

Inputs:

- longer rolling sweep window
- path diversity
- dominant referer ratio

Thresholds:

- `--sweep-window-seconds`
- `--sweep-count`
- `--sweep-unique-paths`
- `--sweep-dominant-referer-ratio`

Good at:

- crawlers that are too slow for burst rules but still too systematic for people

Exact logic:

- maintain a longer rolling window for one IP
- track:
  - total requests in sweep window
  - unique paths in window
  - referer frequency distribution
- compute dominant referer ratio as:
  - `max(referer_count) / window_len`
- heuristic bot condition fires only when all are true:
  - request threshold met
  - unique path threshold met
  - one referer dominates enough

Why referer matters:

- blank referers often dominate scanner traffic
- synthetic repeated referers such as the same landing page can also dominate

### Fast Streak

Inputs:

- inter-request gap
- path changes
- distinct path total

Thresholds:

- `--streak-gap`
- `--streak-count`
- `--streak-unique-total`

Good at:

- short dense path walking

Exact logic:

- compare each row to the previous row for the same IP
- if gap is small enough and path changed:
  - increment streak
- otherwise:
  - reset streak
- heuristic bot condition fires only when both are true:
  - streak length threshold met
  - enough distinct paths were seen across the IP’s total slice

## Per-IP Proof Detectors

### Repeated Pair

Definition:

- repeated adjacent path pairs from the same IP within `--pair-gap-seconds`

Threshold:

- `--pair-repeat-count`

Interpretation:

- synthetic navigation loops
- repeated “article then secondary target” sessions

Exact logic:

- walk adjacent row pairs for one IP in time order
- require:
  - `right.ts - left.ts <= pair_gap_seconds`
  - `left.path != right.path`
- count exact ordered pairs `(left.path, right.path)`
- emit proof when the most common ordered pair repeats enough times

### Tight Multi-Fetch

Definition:

- one IP fetches several non-asset content paths in a short window
- at least some paths are repeated or multiple distinct paths land in the same exact second
- one referer shape dominates the cluster

Thresholds:

- `--multi-fetch-window-seconds`
- `--multi-fetch-count`
- `--multi-fetch-unique-paths`
- `--multi-fetch-repeat-paths`
- `--multi-fetch-same-second-unique-paths`
- `--multi-fetch-dominant-referer-ratio`

Interpretation:

- synthetic tab or page fetch groups
- small crawler batches that are too compact and repetitive for normal reading
- repeated multi-page pulls that stay below broad burst thresholds

Exact logic:

- scan one IP’s rows in time order
- ignore asset-like paths for this detector
- maintain a short sliding window of content requests
- emit proof when the window has:
  - enough requests
  - enough distinct base paths
  - enough dominant referer consistency
  - and either enough repeated base paths or enough same-second distinct base paths

### Asset-Primed Probe

Definition:

- one IP first fetches a content page
- the same short window includes same-page dependency requests with that page as referer
- the same referer then appears on hidden repository/config or discovery probe paths

Thresholds:

- `--exposure-probe-window-seconds`
- `--exposure-probe-asset-count`
- `--exposure-probe-count`

Interpretation:

- browser-like scanners that render enough of the page to look real
- active probes that pivot from a real page into exposed-file discovery
- automation that preserves plausible same-page referers while checking server-side leftovers

Exact logic:

- maintain a short per-IP sliding window
- derive the page path from probe referers
- require a matching content page request in the same window
- require enough same-page dependency requests
- require enough distinct exposed-file probe paths
- require at least one high-risk repository/config probe, so plain discovery-file requests alone do not prove this pattern

### Redundant Revisit

Definition:

- one IP revisits many of the same base paths repeatedly
- the behavior is low-rate enough to evade burst rules
- one referer shape still dominates the whole slice

Thresholds:

- `--revisit-paths`
- `--revisit-repeat-requests`
- `--revisit-dominant-referer-ratio`

Interpretation:

- low-rate crawler or re-checker
- archive revisiter
- repeated machine fetches against the same article set

Exact logic:

- group the IP’s rows by base path
- keep only paths seen at least twice
- compute:
  - number of revisited base paths
  - total extra repeat requests beyond the first visit
  - dominant referer ratio across the full slice
- emit proof only when all are true:
  - enough distinct paths were revisited
  - enough total repeat requests accumulated
  - one referer shape dominates enough

### Low-Context Revisit

Definition:

- one IP repeatedly fetches the same content base path
- every counted request has only direct traffic or a root-page referer
- the repeated fetches span enough time to avoid flagging a single accidental refresh burst

Thresholds:

- `--low-context-revisit-count`
- `--low-context-revisit-min-span-seconds`

Interpretation:

- same-IP low-rate refetchers that do not load enough surrounding context to look like a reader
- repeated direct/root page hits against one article or post

Exact logic:

- keep only `GET` content-page rows with 2xx/3xx status
- collapse query variants to their base path
- classify referers into low-context keys:
  - `direct` for `-`
  - `root:<host>` for root-page referers, with `www.` collapsed
- group by `(base path, low-context referer key)`
- emit proof when the group has enough requests and spans enough seconds

### Rotating UA

Definition:

- one IP shows enough distinct raw UAs and enough distinct UA families across the slice

Thresholds:

- `--rotate-ua-count`
- `--rotate-ua-family-count`

Interpretation:

- browser spoof churn
- traffic synthesis

Exact logic:

- count distinct raw UAs across the IP slice
- also count distinct UA families, where family is a summarized browser/platform grouping
- emit proof only when both counts cross threshold

This means one IP swapping minor Chrome point versions is less interesting than one IP spanning Chrome, Firefox, Safari, Android, Windows, and so on.

### Cadenced Repeat

Definition:

- one IP fetches the same non-asset base path on a stable long-gap cadence
- two hits are enough for the near-hour shortcut when the gap is tightly centered on the configured hourly target
- otherwise, only a few repeats are needed when the interval is highly regular
- one referer shape dominates the cadenced sample

Thresholds:

- `--cadence-repeat-count`
- `--cadence-min-gap-seconds`
- `--cadence-gap-tolerance-seconds`
- `--cadence-dominant-referer-ratio`
- `--cadence-hour-repeat-count`
- `--cadence-hour-gap-seconds`
- `--cadence-hour-gap-tolerance-seconds`

Interpretation:

- scheduled machine re-fetching
- same-second or near-same-second hourly page checks
- low-rate automation that intentionally avoids burst signatures

Exact logic:

- group rows by base path for one IP
- ignore asset-like paths for this detector
- sort each path’s rows by time
- first scan consecutive samples of `cadence_hour_repeat_count`
- emit proof from that shortcut when:
  - every gap is within `cadence_hour_gap_tolerance_seconds` of `cadence_hour_gap_seconds`
  - the sample has enough dominant referer consistency
- scan consecutive samples of `cadence_repeat_count`
- emit proof when:
  - every gap is at least `cadence_min_gap_seconds`
  - the gap spread is within `cadence_gap_tolerance_seconds`
  - the sample has enough dominant referer consistency

### Periodic Poller

Definition:

- same path repeated at one dominant interval

Thresholds:

- `--poll-repeat-count`
- `--poll-min-gap-seconds`

Interpretation:

- scheduled machine polling

Exact logic:

- group rows by exact path for one IP
- for each path:
  - sort rows by time
  - compute integer second gaps between adjacent requests
  - find the modal gap
- emit proof when:
  - one path repeats enough times
  - the dominant gap is large enough
  - that dominant gap occurs often enough

### Serial Sweep

Definition:

- ordered path walk with bounded gaps and enough unique paths

Thresholds:

- `--serial-min-gap-seconds`
- `--serial-max-gap-seconds`
- `--serial-count`
- `--serial-unique-paths`

Interpretation:

- machine-like archive traversal

Exact logic:

- scan rows for one IP in time order
- grow a streak while:
  - gap remains between `serial_min_gap_seconds` and `serial_max_gap_seconds`
  - path changes on each step
- emit proof when the longest such streak has:
  - enough requests
  - enough unique paths

### Payload Fuzzer

Definition:

- enough payload-marker activity plus enough mutation or probe evidence

Inputs:

- payload markers
- payload marker mutation
- injection payloads
- malformed referers

Thresholds:

- `--payload-show-analysis-count`
- `--payload-injection-count`
- `--payload-referer-junk-count`
- `--payload-mutation-count`

Interpretation:

- active feature abuse or probing

Exact logic:

- for one IP, track across the slice:
  - count of payload-marker paths
  - count of injection payloads in path or referer
  - count of malformed referers
  - count of same-base-path mutated pairs close in time
- emit proof only when:
  - payload-marker count reaches threshold
  - and at least one stronger abuse family also reaches threshold:
    - injection count
    - malformed referer count
    - mutation pair count

### Same-Second UA Swap

Definition:

- same IP
- same second
- same base path
- mutated twin requests
- different UAs

Threshold:

- `--same-second-ua-swap-count`

Interpretation:

- deliberate identity manipulation

Exact logic:

- this is a specialized subtype of mutation behavior
- look at adjacent rows and require all of:
  - same IP
  - same integer second
  - same base path
  - full paths differ
  - at least one twin carries a payload marker
  - UAs differ
- count such twin pairs
- emit proof when the count reaches threshold

### Rapid UA Switch

Definition:

- small time window with enough requests, enough distinct UAs, and enough distinct UA families

Thresholds:

- `--ua-switch-window-seconds`
- `--ua-switch-count`
- `--ua-switch-distinct-uas`
- `--ua-switch-distinct-families`

Interpretation:

- implausibly fast identity instability

Exact logic:

- maintain a tiny rolling window over one IP’s time-ordered rows
- count within that window:
  - total requests
  - distinct raw UAs
  - distinct UA families
  - distinct base paths
- emit proof when:
  - request threshold met
  - distinct UA threshold met
  - distinct UA family threshold met

The detector is intentionally generic:

- it does not require exact same URL reuse
- it only treats same-path twin mutations as especially strong examples

## Cross-IP Detectors

### Coordinated UA

Definition:

- one raw UA appears across enough IPs and enough paths in one time window without one IP dominating the traffic

Thresholds:

- `--coord-window-seconds`
- `--coord-count`
- `--coord-unique-paths`
- `--coord-unique-ips`
- `--coord-max-ip-share`
- `--coord-max-rows`

Current overload behavior:

- retains the most recent capped slice instead of disabling detection entirely

Exact logic:

- partition rows by raw UA
- for each raw UA, maintain a sliding time window
- track within that window:
  - total requests
  - unique paths
  - unique IPs
  - largest single-IP share
- emit proof to every IP in the window only when all are true:
  - request threshold met
  - unique path threshold met
  - unique IP threshold met
  - no single IP dominates too much

### Coordinated Target Fanout

Definition:

- one coarse UA family or one exact raw UA
- one repeated base path
- many distinct IPs
- one time window
- one dominant referer shape

Thresholds:

- `--target-fanout-window-seconds`
- `--target-fanout-count`
- `--target-fanout-unique-ips`
- `--target-fanout-max-ip-share`
- `--target-fanout-dominant-referer-ratio`
- `--target-fanout-same-ua-window-seconds`
- `--target-fanout-same-ua-count`
- `--target-fanout-same-ua-unique-ips`
- `--target-fanout-max-rows`

Current overload behavior:

- retains the most recent capped slice instead of disabling detection entirely

Exact logic:

- partition rows by `(coarse UA family, base path)` for the broad mode
- partition rows by `(raw UA, base path)` for the tight exact-UA mode
- for each key, maintain a sliding cross-IP window
- track within that window:
  - total requests
  - unique IPs
  - raw UA variant count
  - largest single-IP share
  - dominant referer ratio
- emit proof to every IP in the window only when all are true:
  - request threshold met
  - unique IP threshold met
  - no single IP dominates too much
  - one referer shape dominates enough

Interpretation:

- distributed “everyone fetch the same page” bot fanout
- social-looking browser spoof traffic focused on one target URL
- exact-UA distributed same-target bursts across separate source IPs
- same-target swarms that evade the broader coordinated-UA detector by not sweeping many paths

### Low-Context Fanout

Definition:

- one content base path appears across many shallow IPs
- each participating IP has only a small number of rows in the scoped slice
- requests have only direct traffic or a root-page referer
- one UA family dominates the fanout

Thresholds:

- `--low-context-fanout-window-seconds`
- `--low-context-fanout-count`
- `--low-context-fanout-unique-ips`
- `--low-context-fanout-max-ip-share`
- `--low-context-fanout-max-ip-requests`
- `--low-context-fanout-min-ua-family-ratio`
- `--low-context-fanout-max-rows`

Current overload behavior:

- candidate rows are capped to the most recent `low_context_fanout_max_rows`

Exact logic:

- keep only `GET` content-page rows with 2xx/3xx status and direct/root referer context
- ignore root paths and static/page-dependency paths
- include only IPs with no more than `low_context_fanout_max_ip_requests` rows in the scoped batch/live state
- group rows by `(base path, low-context referer key)`
- for each group, maintain a sliding time window and track:
  - total requests
  - unique IPs
  - largest single-IP share
  - dominant UA-family ratio
- emit proof to every IP in the window only when all thresholds are met

Interpretation:

- distributed “browser” fetch networks that hit one article once or twice per IP
- root-referrer spoof traffic that looks individually harmless but collectively machine-like
- direct same-target drips where no single IP has enough behavior to classify alone

### Payload Campaign

Definition:

- many IPs collectively express one payload abuse family against enough target paths inside one campaign window

Thresholds:

- `--payload-campaign-window-seconds`
- `--payload-campaign-count`
- `--payload-campaign-unique-ips`
- `--payload-campaign-unique-paths`
- `--payload-campaign-max-rows`

Current overload behavior:

- candidate rows are capped to the most recent `payload_campaign_max_rows`

Exact logic:

- derive a campaign key from:
  - payload family
  - target profile
- payload family itself depends on combinations of:
  - payload-marker presence
  - payload-marker mutation
  - injection payloads
  - malformed referer shape
- then, for each campaign key, maintain a sliding cross-IP window
- track within that window:
  - total requests
  - unique IPs
  - unique base paths
- emit proofs to every IP in the window when all are true:
  - request threshold met
  - unique IP threshold met
  - unique path threshold met
- also maintain the strongest campaign summary for reporting

## Supporting Classifiers

These are not final detectors by themselves but feed proof generation.

### Payload Marker

Config-driven regexes that identify site-specific interesting parameters or query forms.

### Payload Marker Mutation

A payload-marker request becomes mutation-like when the query shows signs such as:

- multiple parameters
- quote-suffixed query
- encoded quotes

### Referer Junk

Detects malformed or suspicious referer shapes.

### Injection Payload

Detects explicit injection-like content in paths or referers.

### Target Profile

Generates structural path buckets like:

- `root`
- `asset`
- `nested`
- `dated-slug`
- `long-slug`
- `slug`
- `short-path`
- `flat-path`

### Payload Family

Converts path and referer behavior into generic campaign families such as:

- `payload-marker-walker`
- `param-mutation`
- `ref-junk-fuzzer`
- `injection-probe`

Exact composition:

- injection present:
  - `injection-probe`
- else mutated payload marker plus referer junk:
  - `ref-junk-fuzzer`
- else mutated payload marker:
  - `param-mutation`
- else payload marker only:
  - `payload-marker-walker`
- else referer junk only:
  - `referer-fuzzer`

Optional suffixes are then added when multiple abuse traits coexist.

## Strong Proof Kinds in Live Mode

In `log-watch`, these proof kinds force `ban` directly:

- `same-second-ua-swap`
- `rapid-ua-switch`
- `tight-multifetch`
- `asset-primed-probe`
- `payload-fuzzer`
- `coordinated-ua`
- `coordinated-target-fanout`
- `low-context-fanout`
- `payload-campaign`
- `repeated-pair`
- `redundant-revisit`
- `low-context-revisit`
- `cadenced-repeat`
- `serial-sweep`
- `periodic-poller`

These are treated as direct `ban` evidence because they are high-confidence behavioral patterns rather than weak statistical hints.

## Costs and Tradeoffs

Cheap detectors:

- known bot pattern
- burst
- HEAD burst
- fast streak

Medium detectors:

- repeated pair
- tight multi-fetch
- asset-primed probe
- rotating UA
- low-context revisit
- cadenced repeat
- serial sweep
- periodic poller

Expensive detectors:

- coordinated UA
- coordinated target fanout
- low-context fanout
- payload campaign
- large live distributed windows

## Guidance for Adding a Detector

A new detector should answer:

1. scope:
   - per-row
   - per-IP
   - cross-IP
2. class:
   - heuristic
   - proof
   - reporting-only
3. evidence:
   - what fields it uses
   - what windows it needs
4. output:
   - score contribution
   - bot flag
   - `ForcedProof`
   - campaign summary
5. operator explanation:
   - what evidence a human would inspect
6. cost:
   - batch
   - live
