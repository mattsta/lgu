# Performance

## Purpose

This document explains the current performance model of LGU, what is fast, what is expensive, what the architecture optimizes for today, and where the remaining bottlenecks are.

## Performance Goals

LGU has two different performance targets.

### Batch target

Make it cheap to answer:

> what are the last N plausible human requests in this scoped slice?

Typical usage:

```bash
tail -n 2000 access.log | uv run log-audit --recent-limit 100
```

### Live target

Make it practical to answer:

> did this new request push an IP or campaign into a state worth alerting on?

Typical usage:

```bash
tail -F access.log | uv run log-watch --output-format fail2ban
```

## Current Batch Performance Model

Batch mode is relatively efficient because it:

- parses matching data once
- sorts once
- canonicalizes once
- builds per-IP stats once
- runs proof detectors over a bounded row set

Important current optimizations:

- raw-byte include-token prefilter before decode
- timestamp day cache
- known-bot match cache by `(ua, referer)`
- cached derived classifiers
- string canonicalization after parse
- unified payload campaign pass
- raw replay by file offsets instead of storing full lines

Best current workload shape:

- recent scoped slices
- one-shot reports
- grouped human inspection

## Current Live Performance Model

For every accepted row, live mode currently:

1. updates per-IP retained rows
2. incrementally updates the per-IP `IPStats` state unless expirations force a local rebuild
3. reruns per-IP proof analysis for that IP
4. incrementally updates the coordinated-UA window for the affected raw UA
5. incrementally updates the payload-campaign window for the affected campaign family
6. composes the final action and applies transition rules

This is substantially cheaper than the old full-window rescanning design and is appropriate for real-time operator workflows and fail2ban eventing.

## Big-O Intuition

### Batch

Roughly:

- parse: linear in matching input size
- sort: `O(n log n)`
- per-IP aggregation: linear
- proof passes: linear to near-linear on grouped data

### Live

Current per-event cost is closer to:

- amortized `O(1)` for per-IP stats updates when no local expirations occur
- `O(ip_window)` for per-IP proof analysis on the current IP
- amortized `O(1)` to `O(ua_window)` for coordinated-UA maintenance on the affected UA
- amortized `O(1)` to `O(campaign_window)` for payload-campaign maintenance on the affected family

That means live cost now scales mainly with the current IP and the current distributed family, not with the whole retained global history.

## Current Bottlenecks

Main bottlenecks:

- per-IP proof analysis on very busy IPs
- large per-family distributed windows
- large retained windows
- full-row retention for proof explainability

## Overload Behavior

Distributed detectors now degrade by bounding live keyed windows instead of disabling themselves entirely.

That is better than the old hard cutoff, but it still means:

- recency-biased degradation
- strongest visibility remains in the currently hottest UA or payload families

## Cheap vs Expensive

Cheap:

- known-bot signature matching with caching
- burst and HEAD-burst aggregation
- fast streak aggregation

Medium:

- repeated pair
- rotating UA
- serial sweep
- periodic poller

Expensive:

- coordinated UA on very large same-UA windows
- payload campaign on very large same-family windows
- per-IP proof analysis for extremely busy IPs

## Practical Tuning

For batch performance:

- scope paths with `--path-include`
- prefer recent-slice analysis through `tail -n`

For live performance:

- narrow path scope where acceptable
- prefer higher-confidence eventing first
- keep live memory windows no larger than necessary

## What Production Performance Means Here

LGU is production-useful today for:

- scoped recent introspection
- batch reporting
- moderate-rate live eventing
- fail2ban enrichment

LGU is not yet fully optimized for:

- very high sustained hostile traffic across many simultaneously hot UAs and campaign families
- approximate-heavy streaming analytics with probabilistic data structures
- fully detached proof generation for ultra-large windows

The remaining gap is mainly about extreme-scale engineering, not correctness of the current live model.
